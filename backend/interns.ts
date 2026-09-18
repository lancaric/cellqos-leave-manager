import type { Express, NextFunction, Request, Response } from "express";
import type { Pool, QueryResultRow } from "pg";
import { randomUUID } from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import os from "os";
import path from "path";
import { HttpError } from "./shared/http-error";
import type { UserRole } from "./shared/types";

type Auth = { userID: string; role: UserRole; email?: string; name?: string };
type AuthedRequest = Request & { auth?: Auth | null };
const execFileAsync = promisify(execFile);

export async function ensureInternSchema(pool: Pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS intern_groups (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, start_date DATE NOT NULL, end_date DATE NOT NULL,
      weekdays INTEGER[] NOT NULL DEFAULT '{}', week_interval INTEGER NOT NULL DEFAULT 1 CHECK (week_interval BETWEEN 1 AND 52), supervisor_user_id TEXT NOT NULL REFERENCES users(id),
      substitute_user_id TEXT REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK (end_date >= start_date)
    );
    CREATE TABLE IF NOT EXISTS interns (
      id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE, group_id BIGINT REFERENCES intern_groups(id) ON DELETE SET NULL,
      start_date DATE, end_date DATE, weekdays INTEGER[] NOT NULL DEFAULT '{}', week_interval INTEGER NOT NULL DEFAULT 1 CHECK (week_interval BETWEEN 1 AND 52),
      supervisor_user_id TEXT REFERENCES users(id), substitute_user_id TEXT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (end_date IS NULL OR start_date IS NULL OR end_date >= start_date)
    );
    CREATE TABLE IF NOT EXISTS intern_attendance (
      id BIGSERIAL PRIMARY KEY, intern_id TEXT NOT NULL REFERENCES interns(id) ON DELETE CASCADE, date DATE NOT NULL,
      status TEXT CHECK (status IN ('PRESENT', 'ABSENT')), reason TEXT, intern_reason TEXT,
      intern_reason_confirmed BOOLEAN NOT NULL DEFAULT FALSE, recorded_by TEXT REFERENCES users(id),
      recorded_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (intern_id, date)
    );
    CREATE INDEX IF NOT EXISTS idx_intern_attendance_date ON intern_attendance(date);
  `);
  await pool.query(`
    ALTER TABLE intern_groups ADD COLUMN IF NOT EXISTS week_interval INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE interns ADD COLUMN IF NOT EXISTS week_interval INTEGER NOT NULL DEFAULT 1;
  `);
}

export async function authenticateIntern(pool: Pool, identifier: string, password: string) {
  const result = await pool.query(
    `SELECT id, email, name, 'INTERN'::text as role, false as "mustChangePassword", true as "profileCompleted"
     FROM interns WHERE lower(email)=lower($1) AND is_active=true AND password_hash=crypt($2,password_hash)`,
    [identifier, password]
  );
  return result.rows[0] ?? null;
}

const asyncRoute = (fn: (req: AuthedRequest, res: Response) => Promise<void>) =>
  (req: AuthedRequest, res: Response, next: NextFunction) => fn(req, res).catch(next);

function auth(req: AuthedRequest) {
  if (!req.auth) throw new HttpError(401, "Authentication required");
  return req.auth;
}
function admin(req: AuthedRequest) {
  const value = auth(req);
  if (value.role !== "ADMIN") throw new HttpError(403, "Táto akcia je dostupná iba administrátorovi.");
  return value;
}
function parseWeekdays(value: unknown): number[] {
  if (!Array.isArray(value)) throw new HttpError(400, "Vyberte aspoň jeden deň praxe.");
  const days = [...new Set(value.map(Number))].filter((day) => Number.isInteger(day) && day >= 1 && day <= 7);
  if (!days.length) throw new HttpError(400, "Vyberte aspoň jeden deň praxe.");
  return days.sort();
}
function requireDates(startDate: unknown, endDate: unknown) {
  const start = String(startDate ?? ""); const end = String(endDate ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end) || end < start) {
    throw new HttpError(400, "Zadajte platné obdobie praxe.");
  }
  return { start, end };
}

const internSelect = `
  SELECT i.id,i.email,i.name,i.is_active as "isActive",i.group_id as "groupId",
    COALESCE(g.start_date,i.start_date)::text as "startDate", COALESCE(g.end_date,i.end_date)::text as "endDate",
    COALESCE(g.weekdays,i.weekdays) as weekdays, COALESCE(g.week_interval,i.week_interval) as "weekInterval", COALESCE(g.supervisor_user_id,i.supervisor_user_id) as "supervisorUserId",
    COALESCE(g.substitute_user_id,i.substitute_user_id) as "substituteUserId", g.name as "groupName",
    s.name as "supervisorName", sub.name as "substituteName"
  FROM interns i LEFT JOIN intern_groups g ON g.id=i.group_id
  LEFT JOIN users s ON s.id=COALESCE(g.supervisor_user_id,i.supervisor_user_id)
  LEFT JOIN users sub ON sub.id=COALESCE(g.substitute_user_id,i.substitute_user_id)`;

export function registerInternRoutes(app: Express, pool: Pool, exportDir: string) {
  app.get("/interns/me", asyncRoute(async (req, res) => {
    const current = auth(req);
    if (current.role !== "INTERN") throw new HttpError(403, "Not an intern account");
    const row = await pool.query(`${internSelect} WHERE i.id=$1`, [current.userID]);
    if (!row.rows[0]) throw new HttpError(404, "Praktikant neexistuje.");
    res.json(row.rows[0]);
  }));

  app.get("/interns/employees", asyncRoute(async (req, res) => {
    admin(req);
    const rows = await pool.query(`SELECT id,name,email,role FROM users WHERE is_active=true ORDER BY name`);
    res.json({ employees: rows.rows });
  }));

  app.get("/intern-groups", asyncRoute(async (req, res) => {
    admin(req);
    const rows = await pool.query(`SELECT g.id,g.name,g.start_date::text as "startDate",g.end_date::text as "endDate",g.weekdays,g.week_interval as "weekInterval",
      g.supervisor_user_id as "supervisorUserId",g.substitute_user_id as "substituteUserId",s.name as "supervisorName",sub.name as "substituteName",
      (SELECT count(*)::int FROM interns i WHERE i.group_id=g.id) as "internCount"
      FROM intern_groups g JOIN users s ON s.id=g.supervisor_user_id LEFT JOIN users sub ON sub.id=g.substitute_user_id ORDER BY g.name`);
    res.json({ groups: rows.rows });
  }));

  app.post("/intern-groups", asyncRoute(async (req, res) => {
    admin(req); const { name, startDate, endDate, supervisorUserId, substituteUserId } = req.body;
    const dates=requireDates(startDate,endDate), weekdays=parseWeekdays(req.body.weekdays), weekInterval=Math.max(1,Math.min(52,Number(req.body.weekInterval)||1));
    if (!String(name ?? "").trim() || !supervisorUserId) throw new HttpError(400,"Názov a poverený zamestnanec sú povinné.");
    const row=await pool.query(`INSERT INTO intern_groups(name,start_date,end_date,weekdays,week_interval,supervisor_user_id,substitute_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,[String(name).trim(),dates.start,dates.end,weekdays,weekInterval,supervisorUserId,substituteUserId||null]);
    res.status(201).json({id:Number(row.rows[0].id)});
  }));

  app.patch("/intern-groups/:id", asyncRoute(async (req, res) => {
    admin(req); const { name,startDate,endDate,supervisorUserId,substituteUserId }=req.body;
    const dates=requireDates(startDate,endDate), weekdays=parseWeekdays(req.body.weekdays), weekInterval=Math.max(1,Math.min(52,Number(req.body.weekInterval)||1));
    const row=await pool.query(`UPDATE intern_groups SET name=$1,start_date=$2,end_date=$3,weekdays=$4,week_interval=$5,supervisor_user_id=$6,
      substitute_user_id=$7,updated_at=NOW() WHERE id=$8 RETURNING id`,[String(name??"").trim(),dates.start,dates.end,weekdays,weekInterval,supervisorUserId,substituteUserId||null,req.params.id]);
    if(!row.rowCount) throw new HttpError(404,"Skupina neexistuje."); res.json({ok:true});
  }));

  app.delete("/intern-groups/:id", asyncRoute(async (req,res)=>{
    admin(req); const used=await pool.query(`SELECT 1 FROM interns WHERE group_id=$1 LIMIT 1`,[req.params.id]);
    if(used.rowCount) throw new HttpError(409,"Skupinu s priradenými praktikantmi nemožno odstrániť.");
    await pool.query(`DELETE FROM intern_groups WHERE id=$1`,[req.params.id]); res.json({ok:true});
  }));

  app.get("/interns", asyncRoute(async (req,res)=>{
    const current=auth(req); let where=""; const values:unknown[]=[];
    if(current.role==="INTERN"){where="WHERE i.id=$1";values.push(current.userID);}
    else if(current.role!=="ADMIN"){where="WHERE COALESCE(g.supervisor_user_id,i.supervisor_user_id)=$1 OR COALESCE(g.substitute_user_id,i.substitute_user_id)=$1";values.push(current.userID);}
    const rows=await pool.query(`${internSelect} ${where} ORDER BY i.name`,values); res.json({interns:rows.rows});
  }));

  app.post("/interns", asyncRoute(async (req,res)=>{
    admin(req); const {email,name,password,groupId,supervisorUserId,substituteUserId}=req.body;
    if(!email||!name||!password||String(password).length<8) throw new HttpError(400,"Meno, e-mail a heslo (min. 8 znakov) sú povinné.");
    let dates:{start:string;end:string}|null=null, weekdays:number[]=[]; const weekInterval=Math.max(1,Math.min(52,Number(req.body.weekInterval)||1));
    if(!groupId){dates=requireDates(req.body.startDate,req.body.endDate);weekdays=parseWeekdays(req.body.weekdays);if(!supervisorUserId)throw new HttpError(400,"Vyberte povereného zamestnanca.");}
    const id=randomUUID(); await pool.query(`INSERT INTO interns(id,email,name,password_hash,group_id,start_date,end_date,weekdays,week_interval,supervisor_user_id,substitute_user_id)
      VALUES($1,lower($2),$3,crypt($4,gen_salt('bf')),$5,$6,$7,$8,$9,$10,$11)`,[id,email,String(name).trim(),password,groupId||null,dates?.start||null,dates?.end||null,weekdays,weekInterval,groupId?null:supervisorUserId,groupId?null:(substituteUserId||null)]);
    res.status(201).json({id});
  }));

  app.patch("/interns/:id", asyncRoute(async (req,res)=>{
    admin(req); const {email,name,groupId,supervisorUserId,substituteUserId,isActive,password}=req.body;
    let dates:{start:string;end:string}|null=null, weekdays:number[]=[]; const weekInterval=Math.max(1,Math.min(52,Number(req.body.weekInterval)||1));
    if(!groupId){dates=requireDates(req.body.startDate,req.body.endDate);weekdays=parseWeekdays(req.body.weekdays);if(!supervisorUserId)throw new HttpError(400,"Vyberte povereného zamestnanca.");}
    const row=await pool.query(`UPDATE interns SET email=lower($1),name=$2,group_id=$3,start_date=$4,end_date=$5,weekdays=$6,week_interval=$7,
      supervisor_user_id=$8,substitute_user_id=$9,is_active=$10,password_hash=CASE WHEN $11::text IS NULL OR $11='' THEN password_hash ELSE crypt($11,gen_salt('bf')) END,updated_at=NOW()
      WHERE id=$12 RETURNING id`,[email,String(name??"").trim(),groupId||null,dates?.start||null,dates?.end||null,weekdays,weekInterval,groupId?null:supervisorUserId,groupId?null:(substituteUserId||null),isActive!==false,password||null,req.params.id]);
    if(!row.rowCount)throw new HttpError(404,"Praktikant neexistuje.");res.json({ok:true});
  }));

  const scheduleSql = `WITH cfg AS (SELECT i.id,i.name,i.group_id,COALESCE(g.start_date,i.start_date) start_date,COALESCE(g.end_date,i.end_date) end_date,
    COALESCE(g.weekdays,i.weekdays) weekdays,COALESCE(g.week_interval,i.week_interval) week_interval,COALESCE(g.supervisor_user_id,i.supervisor_user_id) supervisor_id,
    COALESCE(g.substitute_user_id,i.substitute_user_id) substitute_id FROM interns i LEFT JOIN intern_groups g ON g.id=i.group_id WHERE i.is_active=true),
    scheduled AS (SELECT cfg.*,d::date date FROM cfg CROSS JOIN LATERAL generate_series(GREATEST(cfg.start_date,$1::date),LEAST(cfg.end_date,$2::date),'1 day') d
      WHERE EXTRACT(ISODOW FROM d)::int=ANY(cfg.weekdays) AND MOD(FLOOR((d::date-cfg.start_date)/7.0)::int,cfg.week_interval)=0)
    SELECT s.id as "internId",s.name as "internName",s.group_id as "groupId",s.date::text,a.status,a.reason,a.intern_reason as "internReason",
      a.intern_reason_confirmed as "internReasonConfirmed",a.recorded_by as "recordedBy",a.recorded_at as "recordedAt",s.supervisor_id as "supervisorUserId",s.substitute_id as "substituteUserId"
    FROM scheduled s LEFT JOIN intern_attendance a ON a.intern_id=s.id AND a.date=s.date`;

  app.get("/intern-attendance", asyncRoute(async(req,res)=>{
    const current=auth(req), {start,end}=requireDates(req.query.from,req.query.to); const values:unknown[]=[start,end]; let scope="";
    if(current.role==="INTERN"){values.push(current.userID);scope=` AND s.id=$3`;}
    else if(current.role!=="ADMIN"){values.push(current.userID);scope=` AND (s.supervisor_id=$3 OR s.substitute_id=$3)`;}
    if(req.query.internId){values.push(String(req.query.internId));scope+=` AND s.id=$${values.length}`;}
    if(req.query.groupId){values.push(Number(req.query.groupId));scope+=` AND s.group_id=$${values.length}`;}
    const rows=await pool.query(`${scheduleSql} WHERE true ${scope} ORDER BY s.date,s.name`,values);res.json({records:rows.rows});
  }));

  app.put("/intern-attendance/:internId/:date", asyncRoute(async(req,res)=>{
    const current=auth(req); if(current.role==="INTERN")throw new HttpError(403,"Dochádzku zapisuje poverený zamestnanec.");
    const status=req.body.status; if(!["PRESENT","ABSENT"].includes(status))throw new HttpError(400,"Neplatný stav dochádzky.");
    const allowed=await pool.query(`${scheduleSql} WHERE s.id=$3 AND s.date=$4::date AND ($5='ADMIN' OR s.supervisor_id=$6 OR s.substitute_id=$6)`,[req.params.date,req.params.date,req.params.internId,req.params.date,current.role,current.userID]);
    if(!allowed.rowCount)throw new HttpError(403,"Tento deň alebo praktikant nie je vo vašej správe.");
    await pool.query(`INSERT INTO intern_attendance(intern_id,date,status,reason,intern_reason_confirmed,recorded_by,recorded_at)
      VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(intern_id,date) DO UPDATE SET status=$3,reason=$4,
      intern_reason_confirmed=$5,recorded_by=$6,recorded_at=NOW(),updated_at=NOW()`,[req.params.internId,req.params.date,status,status==="ABSENT"?(req.body.reason||null):null,Boolean(req.body.confirmInternReason),current.userID]);
    res.json({ok:true});
  }));

  app.post("/intern-attendance/:date/absence", asyncRoute(async(req,res)=>{
    const current=auth(req);if(current.role!=="INTERN")throw new HttpError(403,"Táto akcia je iba pre praktikanta.");
    const today=new Date().toISOString().slice(0,10);if(req.params.date<=today)throw new HttpError(400,"Dôvod možno zadať iba vopred.");
    const scheduled=await pool.query(`${scheduleSql} WHERE s.id=$3 AND s.date=$4::date`,[req.params.date,req.params.date,current.userID,req.params.date]);
    if(!scheduled.rowCount)throw new HttpError(400,"V tento deň nemáte naplánovanú prax.");
    await pool.query(`INSERT INTO intern_attendance(intern_id,date,intern_reason,intern_reason_confirmed) VALUES($1,$2,$3,false)
      ON CONFLICT(intern_id,date) DO UPDATE SET intern_reason=$3,intern_reason_confirmed=false,updated_at=NOW()`,[current.userID,req.params.date,String(req.body.reason??"").trim()||null]);res.json({ok:true});
  }));

  app.get("/intern-attendance/export", asyncRoute(async(req,res)=>{
    const current=auth(req);if(current.role==="INTERN")throw new HttpError(403,"Export vytvára poverený zamestnanec alebo administrátor.");
    const {start,end}=requireDates(req.query.from,req.query.to), internId=String(req.query.internId??""), groupId=Number(req.query.groupId)||null;
    const values:unknown[]=[start,end];
    const filters:string[]=[];
    if(internId){values.push(internId);filters.push(`s.id=$${values.length}`);}
    if(groupId){values.push(groupId);filters.push(`s.group_id=$${values.length}`);}
    values.push(current.role);const roleIndex=values.length;
    values.push(current.userID);const userIndex=values.length;
    filters.push(`($${roleIndex}='ADMIN' OR s.supervisor_id=$${userIndex} OR s.substitute_id=$${userIndex})`);
    const rows=await pool.query(`${scheduleSql} WHERE ${filters.join(" AND ")} ORDER BY s.name,s.date`,values);
    if(!rows.rowCount)throw new HttpError(404,"Pre zvolené obdobie neboli nájdené dni praxe.");
    const internIds=[...new Set(rows.rows.map((row)=>String(row.internId)))];
    const info=await pool.query(`${internSelect} WHERE i.id=ANY($1::text[]) ORDER BY i.name`,[internIds]); const temporary=await fs.promises.mkdtemp(path.join(os.tmpdir(),"intern-attendance-"));
    const input=path.join(temporary,"data.json"),output=path.join(temporary,"attendance.pdf");
    try{await fs.promises.writeFile(input,JSON.stringify({interns:info.rows,from:start,to:end,records:rows.rows}),"utf8");
      const script=path.join(exportDir,"generate_attendance.py"); let error:unknown;
      for(const [bin,args] of [["python",[]],["py",["-3"]],["python3",[]]] as [string,string[]][]){try{await execFileAsync(bin,[...args,script,"--input",input,"--output",output],{cwd:exportDir});error=null;break;}catch(e){error=e;}}
      if(error)throw error; const pdf=await fs.promises.readFile(output);res.setHeader("Content-Type","application/pdf");res.setHeader("Content-Disposition",`attachment; filename=dochadzka-${start}-${end}.pdf`);res.send(pdf);
    }finally{await fs.promises.rm(temporary,{recursive:true,force:true});}
  }));
}
