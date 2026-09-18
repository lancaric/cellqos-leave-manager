import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import moment from "moment";
import { Download, Plus, Save } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { useBackend } from "@/lib/backend";
import { useToast } from "@/components/ui/use-toast";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const weekdays = [{id:1,label:"Po"},{id:2,label:"Ut"},{id:3,label:"St"},{id:4,label:"Št"},{id:5,label:"Pi"},{id:6,label:"So"},{id:7,label:"Ne"}];
const emptySettings = { name:"", startDate:"", endDate:"", weekdays:[1] as number[], weekInterval:1, supervisorUserId:"", substituteUserId:"" };
const thisMonth = () => ({ from: moment().startOf("month").format("YYYY-MM-DD"), to: moment().endOf("month").format("YYYY-MM-DD") });

function DayPicker({value,onChange}:{value:number[];onChange:(v:number[])=>void}) {
  return <div className="flex flex-wrap gap-3">{weekdays.map(day=><label key={day.id} className="flex items-center gap-2 text-sm"><Checkbox checked={value.includes(day.id)} onCheckedChange={checked=>onChange(checked?[...value,day.id].sort() : value.filter(v=>v!==day.id))}/>{day.label}</label>)}</div>;
}

export default function InternsPage(){
  const {user}=useAuth();
  return <div className="space-y-6"><div><h1 className="text-2xl font-bold sm:text-3xl">Prax a dochádzka</h1><p className="text-muted-foreground">Evidencia plánovaných dní a dochádzky praktikantov.</p></div>
    {user?.role==="ADMIN"?<AdminPanel/>:<AttendancePanel internView={user?.role==="INTERN"}/>}</div>;
}

function AdminPanel(){
  return <Tabs defaultValue="attendance"><TabsList className="flex h-auto flex-wrap"><TabsTrigger value="attendance">Dochádzka</TabsTrigger><TabsTrigger value="interns">Praktikanti</TabsTrigger><TabsTrigger value="groups">Skupiny</TabsTrigger></TabsList>
    <TabsContent value="attendance" className="mt-5"><AttendancePanel internView={false}/></TabsContent>
    <TabsContent value="interns" className="mt-5"><InternManagement/></TabsContent>
    <TabsContent value="groups" className="mt-5"><GroupManagement/></TabsContent></Tabs>;
}

function GroupManagement(){
  const backend=useBackend(),qc=useQueryClient(),{toast}=useToast(); const [form,setForm]=useState({...emptySettings}); const [editing,setEditing]=useState<number|null>(null);
  const groups=useQuery({queryKey:["intern-groups"],queryFn:()=>backend.interns.groups.list()});
  const employees=useQuery({queryKey:["intern-employees"],queryFn:()=>backend.interns.employees()});
  const save=useMutation({mutationFn:()=>editing?backend.interns.groups.update({id:editing,...form}):backend.interns.groups.create(form),onSuccess:()=>{toast({title:"Skupina bola uložená."});setForm({...emptySettings});setEditing(null);qc.invalidateQueries({queryKey:["intern-groups"]});},onError:(e:any)=>toast({title:"Uloženie zlyhalo",description:e.message,variant:"destructive"})});
  const remove=useMutation({mutationFn:(id:number)=>backend.interns.groups.remove(id),onSuccess:()=>qc.invalidateQueries({queryKey:["intern-groups"]}),onError:(e:any)=>toast({title:"Odstránenie zlyhalo",description:e.message,variant:"destructive"})});
  const edit=(g:any)=>{setEditing(Number(g.id));setForm({name:g.name,startDate:g.startDate,endDate:g.endDate,weekdays:g.weekdays,weekInterval:g.weekInterval||1,supervisorUserId:g.supervisorUserId,substituteUserId:g.substituteUserId||""});};
  return <div className="grid gap-5 lg:grid-cols-[380px_1fr]"><SettingsForm title={editing?"Upraviť skupinu":"Nová skupina"} form={form} setForm={setForm} employees={employees.data?.employees||[]} onSave={()=>save.mutate()} cancel={editing?()=>{setEditing(null);setForm({...emptySettings});}:undefined}/>
    <Card className="p-4"><Table><TableHeader><TableRow><TableHead>Skupina</TableHead><TableHead>Obdobie a dni</TableHead><TableHead>Poverený</TableHead><TableHead>Počet</TableHead><TableHead/></TableRow></TableHeader><TableBody>{(groups.data?.groups||[]).map((g:any)=><TableRow key={g.id}><TableCell>{g.name}</TableCell><TableCell>{g.startDate} – {g.endDate}<br/><span className="text-muted-foreground">{g.weekdays.map((d:number)=>weekdays.find(w=>w.id===d)?.label).join(", ")}</span></TableCell><TableCell>{g.supervisorName}{g.substituteName&&<><br/><span className="text-muted-foreground">Zástupca: {g.substituteName}</span></>}</TableCell><TableCell>{g.internCount}</TableCell><TableCell className="space-x-2"><Button size="sm" variant="outline" onClick={()=>edit(g)}>Upraviť</Button><Button size="sm" variant="destructive" onClick={()=>remove.mutate(Number(g.id))}>Odstrániť</Button></TableCell></TableRow>)}</TableBody></Table></Card></div>;
}

function SettingsForm({title,form,setForm,employees,onSave,cancel}:{title:string;form:any;setForm:(v:any)=>void;employees:any[];onSave:()=>void;cancel?:()=>void}){
  return <Card className="space-y-4 p-4"><h2 className="font-semibold">{title}</h2><div><Label>Názov</Label><Input value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></div><div className="grid grid-cols-2 gap-3"><div><Label>Od</Label><Input type="date" value={form.startDate} onChange={e=>setForm({...form,startDate:e.target.value})}/></div><div><Label>Do</Label><Input type="date" value={form.endDate} onChange={e=>setForm({...form,endDate:e.target.value})}/></div></div><div><Label>Dni praxe</Label><DayPicker value={form.weekdays} onChange={v=>setForm({...form,weekdays:v})}/></div><div><Label>Opakovanie (každý N-týždeň)</Label><Input type="number" min={1} max={52} value={form.weekInterval} onChange={e=>setForm({...form,weekInterval:Number(e.target.value)})}/></div><div><Label>Poverený zamestnanec</Label><select className="h-9 w-full rounded-md border bg-background px-3" value={form.supervisorUserId} onChange={e=>setForm({...form,supervisorUserId:e.target.value})}><option value="">Vyberte...</option>{employees.map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select></div><div><Label>Zástupca (voliteľné)</Label><select className="h-9 w-full rounded-md border bg-background px-3" value={form.substituteUserId} onChange={e=>setForm({...form,substituteUserId:e.target.value})}><option value="">Bez zástupcu</option>{employees.filter(e=>e.id!==form.supervisorUserId).map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select></div><div className="flex gap-2"><Button onClick={onSave}><Save className="mr-2 h-4 w-4"/>Uložiť</Button>{cancel&&<Button variant="outline" onClick={cancel}>Zrušiť</Button>}</div></Card>;
}

function InternManagement(){
  const backend=useBackend(),qc=useQueryClient(),{toast}=useToast();const [editing,setEditing]=useState<string|null>(null);
  const [form,setForm]=useState({...emptySettings,email:"",password:"",groupId:"",isActive:true});
  const interns=useQuery({queryKey:["interns"],queryFn:()=>backend.interns.list()});const groups=useQuery({queryKey:["intern-groups"],queryFn:()=>backend.interns.groups.list()});const employees=useQuery({queryKey:["intern-employees"],queryFn:()=>backend.interns.employees()});
  const save=useMutation({mutationFn:()=>{const payload={...form,groupId:form.groupId?Number(form.groupId):null};return editing?backend.interns.update({id:editing,...payload}):backend.interns.create(payload);},onSuccess:()=>{toast({title:"Praktikant bol uložený."});setEditing(null);setForm({...emptySettings,email:"",password:"",groupId:"",isActive:true});qc.invalidateQueries({queryKey:["interns"]});},onError:(e:any)=>toast({title:"Uloženie zlyhalo",description:e.message,variant:"destructive"})});
  const edit=(i:any)=>{setEditing(i.id);setForm({name:i.name,email:i.email,password:"",groupId:i.groupId?String(i.groupId):"",startDate:i.startDate,endDate:i.endDate,weekdays:i.weekdays,weekInterval:i.weekInterval||1,supervisorUserId:i.supervisorUserId||"",substituteUserId:i.substituteUserId||"",isActive:i.isActive});};
  return <div className="grid gap-5 lg:grid-cols-[400px_1fr]"><Card className="space-y-4 p-4"><h2 className="font-semibold">{editing?"Upraviť praktikanta":"Nový praktikant"}</h2><div><Label>Meno</Label><Input value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></div><div><Label>E-mail (prihlasovacie meno)</Label><Input type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})}/></div><div><Label>{editing?"Nové heslo (ponechajte prázdne bez zmeny)":"Heslo (min. 8 znakov)"}</Label><Input type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/></div><div><Label>Skupina</Label><select className="h-9 w-full rounded-md border bg-background px-3" value={form.groupId} onChange={e=>setForm({...form,groupId:e.target.value})}><option value="">Individuálne nastavenie</option>{(groups.data?.groups||[]).map((g:any)=><option key={g.id} value={g.id}>{g.name}</option>)}</select></div>{form.groupId?<p className="rounded-md bg-muted p-3 text-sm">Obdobie, dni a poverení zamestnanci sa preberajú zo skupiny a nemožno ich upraviť individuálne.</p>:<SettingsFormFields form={form} setForm={setForm} employees={employees.data?.employees||[]}/>} {editing&&<label className="flex gap-2"><Checkbox checked={form.isActive} onCheckedChange={v=>setForm({...form,isActive:Boolean(v)})}/>Aktívny účet</label>}<div className="flex gap-2"><Button onClick={()=>save.mutate()}><Plus className="mr-2 h-4 w-4"/>{editing?"Uložiť":"Pridať"}</Button>{editing&&<Button variant="outline" onClick={()=>{setEditing(null);setForm({...emptySettings,email:"",password:"",groupId:"",isActive:true});}}>Zrušiť</Button>}</div></Card>
    <Card className="p-4"><Table><TableHeader><TableRow><TableHead>Praktikant</TableHead><TableHead>Nastavenie</TableHead><TableHead>Poverený</TableHead><TableHead>Stav</TableHead><TableHead/></TableRow></TableHeader><TableBody>{(interns.data?.interns||[]).map((i:any)=><TableRow key={i.id}><TableCell>{i.name}<br/><span className="text-muted-foreground">{i.email}</span></TableCell><TableCell>{i.groupName||"Individuálne"}<br/><span className="text-muted-foreground">{i.startDate} – {i.endDate}</span></TableCell><TableCell>{i.supervisorName}</TableCell><TableCell><Badge variant={i.isActive?"default":"secondary"}>{i.isActive?"Aktívny":"Neaktívny"}</Badge></TableCell><TableCell><Button size="sm" variant="outline" onClick={()=>edit(i)}>Upraviť</Button></TableCell></TableRow>)}</TableBody></Table></Card></div>;
}
function SettingsFormFields({form,setForm,employees}:{form:any;setForm:(v:any)=>void;employees:any[]}){return <><div className="grid grid-cols-2 gap-3"><div><Label>Od</Label><Input type="date" value={form.startDate} onChange={e=>setForm({...form,startDate:e.target.value})}/></div><div><Label>Do</Label><Input type="date" value={form.endDate} onChange={e=>setForm({...form,endDate:e.target.value})}/></div></div><div><Label>Dni praxe</Label><DayPicker value={form.weekdays} onChange={v=>setForm({...form,weekdays:v})}/></div><div><Label>Opakovanie (každý N-týždeň)</Label><Input type="number" min={1} max={52} value={form.weekInterval} onChange={e=>setForm({...form,weekInterval:Number(e.target.value)})}/></div><div><Label>Poverený zamestnanec</Label><select className="h-9 w-full rounded-md border bg-background px-3" value={form.supervisorUserId} onChange={e=>setForm({...form,supervisorUserId:e.target.value})}><option value="">Vyberte...</option>{employees.map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select></div><div><Label>Zástupca</Label><select className="h-9 w-full rounded-md border bg-background px-3" value={form.substituteUserId} onChange={e=>setForm({...form,substituteUserId:e.target.value})}><option value="">Bez zástupcu</option>{employees.filter(e=>e.id!==form.supervisorUserId).map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select></div></>}

function AttendancePanel({ internView }: { internView: boolean }) {
  const backend = useBackend();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const initial = thisMonth();
  const [from, setFrom] = useState(initial.from);
  const [to, setTo] = useState(initial.to);
  const [attendanceScope, setAttendanceScope] = useState("");
  const [drafts, setDrafts] = useState<Record<string, any>>({});
  const [absenceDrafts, setAbsenceDrafts] = useState<Record<string, string>>({});

  const interns = useQuery({ queryKey: ["interns"], queryFn: () => backend.interns.list() });
  const availableInterns = interns.data?.interns || [];
  const availableGroups = useMemo(() => Array.from(
    new Map(availableInterns.filter((intern: any) => intern.groupId).map((intern: any) => [String(intern.groupId), { id: Number(intern.groupId), name: intern.groupName }])).values()
  ) as Array<{ id: number; name: string }>, [availableInterns]);
  const selectedInternId = attendanceScope.startsWith("intern:") ? attendanceScope.slice(7) : undefined;
  const selectedGroupId = attendanceScope.startsWith("group:") ? Number(attendanceScope.slice(6)) : undefined;
  const records = useQuery({
    queryKey: ["intern-attendance", from, to, attendanceScope],
    queryFn: () => backend.interns.attendance({ from, to, internId: selectedInternId, groupId: selectedGroupId }),
  });
  const rows = records.data?.records || [];
  const selectedGroupInternIds = useMemo(() => new Set(
    selectedGroupId
      ? availableInterns.filter((intern: any) => Number(intern.groupId) === selectedGroupId).map((intern: any) => String(intern.id))
      : []
  ), [availableInterns, selectedGroupId]);
  const visibleRows = selectedGroupId
    ? rows.filter((row: any) => Number(row.groupId) === selectedGroupId || selectedGroupInternIds.has(String(row.internId)))
    : selectedInternId
      ? rows.filter((row: any) => String(row.internId) === selectedInternId)
      : rows;
  const today = moment().format("YYYY-MM-DD");
  const pending = visibleRows.filter((row: any) => !row.status && row.date <= today).length;

  const record = useMutation({
    mutationFn: ({ row, value }: { row: any; value: any }) => backend.interns.record(row.internId, row.date, value),
    onSuccess: (_data, variables) => {
      const key = `${variables.row.internId}-${variables.row.date}`;
      setDrafts((current) => { const next = { ...current }; delete next[key]; return next; });
      toast({ title: "Dochádzka bola uložená." });
      queryClient.invalidateQueries({ queryKey: ["intern-attendance"] });
    },
    onError: (error: any) => toast({ title: "Uloženie zlyhalo", description: error.message, variant: "destructive" }),
  });
  const absence = useMutation({
    mutationFn: ({ date, reason }: { date: string; reason: string }) => backend.interns.absence(date, reason),
    onSuccess: (_data, variables) => {
      setAbsenceDrafts((current) => { const next = { ...current }; delete next[variables.date]; return next; });
      toast({ title: "Dôvod bol odoslaný na potvrdenie." });
      queryClient.invalidateQueries({ queryKey: ["intern-attendance"] });
    },
    onError: (error: any) => toast({ title: "Odoslanie zlyhalo", description: error.message, variant: "destructive" }),
  });
  const doExport = async () => {
    try {
      const blob = await backend.interns.exportPdf({ from, to, internId: selectedInternId, groupId: selectedGroupId });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `dochadzka-${attendanceScope.replace(":", "-") || "vsetci"}-${from}-${to}.pdf`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (error: any) {
      toast({ title: "Export zlyhal", description: error.message, variant: "destructive" });
    }
  };
  const grouped = useMemo(() => visibleRows.reduce((acc: any, row: any) => {
    (acc[row.date] ??= []).push(row); return acc;
  }, {}), [visibleRows]);

  return <div className="space-y-4">
    <Card className="flex flex-wrap items-end gap-3 p-4">
      <div><Label>Od</Label><Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} /></div>
      <div><Label>Do</Label><Input type="date" value={to} onChange={(event) => setTo(event.target.value)} /></div>
      {!internView && <div><Label>Praktikant</Label><select className="h-9 min-w-64 rounded-md border bg-background px-3" value={attendanceScope} onChange={(event) => setAttendanceScope(event.target.value)}><option value="">Všetci</option>{availableGroups.map((group) => <option key={`group-${group.id}`} value={`group:${group.id}`}>Všetci zo skupiny {group.name}</option>)}{availableInterns.map((intern: any) => <option key={intern.id} value={`intern:${intern.id}`}>{intern.name}</option>)}</select></div>}
      {!internView && <Button variant="outline" onClick={doExport}><Download className="mr-2 h-4 w-4" />Export PDF</Button>}
      {!internView && pending > 0 && <Badge variant="destructive">Nezaevidované: {pending}</Badge>}
    </Card>
    {visibleRows.length === 0 ? <Card className="p-8 text-center text-muted-foreground">V zvolenom období nie sú naplánované dni praxe.</Card> :
      <Card className="p-4"><Table><TableHeader><TableRow><TableHead>Dátum</TableHead>{!internView && <TableHead>Praktikant</TableHead>}<TableHead>Stav</TableHead><TableHead>Dôvod</TableHead><TableHead /></TableRow></TableHeader><TableBody>
        {Object.values(grouped).flat().map((row: any) => {
          const key = `${row.internId}-${row.date}`;
          const original = { status: row.status || "", reason: row.reason || "", confirmInternReason: row.internReasonConfirmed || false };
          const draft = drafts[key] || original;
          const isDirty = draft.status !== original.status || draft.reason !== original.reason || draft.confirmInternReason !== original.confirmInternReason;
          const absenceValue = absenceDrafts[row.date] ?? row.internReason ?? "";
          const absenceDirty = Object.prototype.hasOwnProperty.call(absenceDrafts, row.date) && absenceValue.trim().length > 0 && absenceValue !== (row.internReason || "");
          return <TableRow key={key}>
            <TableCell>{moment(row.date).format("dd D. M. YYYY")}</TableCell>
            {!internView && <TableCell>{row.internName}</TableCell>}
            <TableCell>{internView ? <Badge variant={row.status === "PRESENT" ? "default" : row.status === "ABSENT" ? "destructive" : "secondary"}>{row.status === "PRESENT" ? "Prítomný" : row.status === "ABSENT" ? "Neprítomný" : "Nezaevidované"}</Badge> :
              <select className="h-9 rounded-md border bg-background px-2" value={draft.status} onChange={(event) => setDrafts((current) => ({ ...current, [key]: { ...draft, status: event.target.value } }))}><option value="">Vyberte...</option><option value="PRESENT">Prítomný</option><option value="ABSENT">Neprítomný</option></select>}
            </TableCell>
            <TableCell>{internView ? (row.reason || (row.internReasonConfirmed ? row.internReason : "—")) : <div className="space-y-2">
              {draft.status === "ABSENT" && <Input placeholder="Dôvod (voliteľný)" value={draft.reason} onChange={(event) => setDrafts((current) => ({ ...current, [key]: { ...draft, reason: event.target.value } }))} />}
              {row.internReason && <label className="flex items-center gap-2 text-sm"><Checkbox checked={draft.confirmInternReason} onCheckedChange={(value) => setDrafts((current) => ({ ...current, [key]: { ...draft, confirmInternReason: Boolean(value) } }))} />Potvrdiť dôvod praktikanta: „{row.internReason}“</label>}
            </div>}</TableCell>
            <TableCell>{internView ? (row.date > today && !row.status ? <div className="flex gap-2"><Input placeholder="Budúci dôvod neprítomnosti" value={absenceValue} onChange={(event) => setAbsenceDrafts((current) => ({ ...current, [row.date]: event.target.value }))} />{absenceDirty && <Button size="sm" onClick={() => absence.mutate({ date: row.date, reason: absenceValue })}>Odoslať</Button>}</div> : null) :
              <div className="flex items-center gap-2">{isDirty && <Button size="sm" disabled={!draft.status} onClick={() => record.mutate({ row, value: draft })}>Uložiť</Button>}{!row.status && <span className="h-2.5 w-2.5 rounded-full bg-red-500" title="Dochádzka ešte nie je zaevidovaná" aria-label="Dochádzka ešte nie je zaevidovaná" />}</div>}
            </TableCell>
          </TableRow>;
        })}
      </TableBody></Table></Card>}
  </div>;
}
