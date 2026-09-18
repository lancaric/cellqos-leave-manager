CREATE TABLE intern_groups (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  start_date DATE NOT NULL,
  end_date DATE NOT NULL,
  weekdays INTEGER[] NOT NULL DEFAULT '{}',
  week_interval INTEGER NOT NULL DEFAULT 1 CHECK (week_interval BETWEEN 1 AND 52),
  supervisor_user_id TEXT NOT NULL REFERENCES users(id),
  substitute_user_id TEXT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT intern_groups_dates CHECK (end_date >= start_date)
);

CREATE TABLE interns (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  group_id BIGINT REFERENCES intern_groups(id) ON DELETE SET NULL,
  start_date DATE,
  end_date DATE,
  weekdays INTEGER[] NOT NULL DEFAULT '{}',
  week_interval INTEGER NOT NULL DEFAULT 1 CHECK (week_interval BETWEEN 1 AND 52),
  supervisor_user_id TEXT REFERENCES users(id),
  substitute_user_id TEXT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT interns_dates CHECK (end_date IS NULL OR start_date IS NULL OR end_date >= start_date),
  CONSTRAINT interns_configuration CHECK (group_id IS NOT NULL OR (start_date IS NOT NULL AND end_date IS NOT NULL AND supervisor_user_id IS NOT NULL))
);

CREATE TABLE intern_attendance (
  id BIGSERIAL PRIMARY KEY,
  intern_id TEXT NOT NULL REFERENCES interns(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  status TEXT CHECK (status IN ('PRESENT', 'ABSENT')),
  reason TEXT,
  intern_reason TEXT,
  intern_reason_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  recorded_by TEXT REFERENCES users(id),
  recorded_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (intern_id, date)
);

CREATE INDEX idx_interns_supervisors ON interns(supervisor_user_id, substitute_user_id);
CREATE INDEX idx_intern_attendance_date ON intern_attendance(date);
