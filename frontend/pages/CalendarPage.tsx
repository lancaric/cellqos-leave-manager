import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Calendar as BigCalendar, momentLocalizer } from "react-big-calendar";
import moment from "moment";
import "moment/locale/sk";
import { useBackend } from "@/lib/backend";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";
import RequestFormDialog from "@/components/requests/RequestFormDialog";
import RequestDetailDialog from "@/components/requests/RequestDetailDialog";
import "react-big-calendar/lib/css/react-big-calendar.css";
import "./calendar.css";
import { Badge } from "@/components/ui/badge";

const localizer = momentLocalizer(moment);
moment.locale("sk");

interface CalendarEvent {
  id: number | string;
  title: string;
  start: Date;
  end: Date;
  allDay?: boolean;
  resource: any;
}

type CalendarView = "month" | "week" | "work_week" | "day" | "agenda";

export default function CalendarPage() {
  const backend = useBackend();
  const [date, setDate] = useState(new Date());
  const [view, setView] = useState<CalendarView>("month");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [selectedRange, setSelectedRange] = useState<{
    startDate: string;
    endDate: string;
  } | null>(null);

  const getViewUnit = (v: CalendarView) => {
    if (v === "agenda" || v === "work_week") return "month";
    return v as "day" | "week" | "month";
  };

  const startDate = moment(date).startOf(getViewUnit(view)).format("YYYY-MM-DD");
  const endDate = moment(date).endOf(getViewUnit(view)).format("YYYY-MM-DD");

  const { data } = useQuery({
    queryKey: ["calendar", startDate, endDate],
    queryFn: async () => {
      return backend.calendar.get({ startDate, endDate });
    },
  });

  const { data: namedayData } = useQuery({
    queryKey: ["namedays-today"],
    queryFn: async () => backend.namedays.today(),
    staleTime: 1000 * 60 * 30,
  });

  const { data: holidayData } = useQuery({
    queryKey: ["calendar-holidays", startDate, endDate],
    queryFn: async () => {
      const rangeStart = moment(startDate, "YYYY-MM-DD", true);
      const rangeEnd = moment(endDate, "YYYY-MM-DD", true);
      if (!rangeStart.isValid() || !rangeEnd.isValid()) {
        return { holidays: [] };
      }
      const start = moment.min(rangeStart, rangeEnd);
      const end = moment.max(rangeStart, rangeEnd);
      const years = Array.from(
        { length: end.year() - start.year() + 1 },
        (_, index) => start.year() + index
      );
      const holidayResponses = await Promise.all(years.map((year) => backend.holidays.list({ year })));
      const holidays = holidayResponses.flatMap((response) => response.holidays || []);
      const inRange = holidays.filter((holiday) => {
        const holidayMoment = moment(holiday.date, "YYYY-MM-DD", true);
        return holidayMoment.isValid() && holidayMoment.isBetween(start, end, "day", "[]");
      });
      return { holidays: inRange };
    },
  });

  const typeLabels = {
    ANNUAL_LEAVE: "Dovolenka",
    SICK_LEAVE: "PN",
    HOME_OFFICE: "Home office",
    UNPAID_LEAVE: "Neplatené voľno",
    OTHER: "Iné",
  };

  const resolveTime = (timeValue?: string | null, fallbackTime = "00:00:00") => {
    if (!timeValue) return fallbackTime;
    if (timeValue.length === 5) return `${timeValue}:00`;
    return timeValue.slice(0, 8);
  };

  const buildEventDateTime = (
    dateValue: string,
    timeValue?: string | null,
    fallbackTime = "00:00:00"
  ) => {
    const datePart = dateValue.slice(0, 10);
    const timePart = resolveTime(timeValue, fallbackTime);
    return moment(`${datePart}T${timePart}`).toDate();
  };

  const events: CalendarEvent[] = (data?.events || []).map((event) => {
    const kind = event.kind ?? "LEAVE";

    if (kind === "BIRTHDAY") {
      const title = `Narodeniny: ${event.userName}${typeof event.age === "number" ? ` (${event.age})` : ""}`;
      return {
        id: event.id,
        title,
        start: moment(event.startDate).startOf("day").toDate(),
        end: moment(event.startDate).startOf("day").add(1, "day").toDate(),
        allDay: true,
        resource: { ...event, kind },
      };
    }

    const hasTimeRange = Boolean(event.startTime || event.endTime);
    const start = hasTimeRange
      ? buildEventDateTime(event.startDate, event.startTime, "00:00:00")
      : moment(event.startDate).startOf("day").toDate();
    const end = hasTimeRange
      ? buildEventDateTime(event.endDate, event.endTime, "23:59:59")
      : moment(event.endDate).startOf("day").add(1, "day").toDate();

    return {
      id: event.id,
      title: `${event.userName} - ${
        typeLabels[event.type as keyof typeof typeLabels] ?? event.type.replace("_", " ")
      }`,
      start,
      end,
      allDay: !hasTimeRange,
      resource: { ...event, kind },
    };
  });

  const holidayEvents: CalendarEvent[] = (holidayData?.holidays || []).map((holiday) => ({
    id: `holiday-${holiday.id}`,
    title: `Sviatok: ${holiday.name}`,
    start: moment(holiday.date).startOf("day").toDate(),
    end: moment(holiday.date).startOf("day").add(1, "day").toDate(),
    allDay: true,
    resource: { ...holiday, kind: "HOLIDAY" },
  }));

  const calendarEvents = [...events, ...holidayEvents];

  const eventStyleGetter = (event: CalendarEvent) => {
    if (event.resource?.kind === "HOLIDAY") {
      return { className: "holiday-event" };
    }

    if (event.resource?.kind === "BIRTHDAY") {
      return { className: "birthday-event" };
    }

    const status = event.resource.status;
    const colors = {
      PENDING: "bg-yellow-500",
      APPROVED: "bg-green-500",
      REJECTED: "bg-red-500",
      CANCELLED: "bg-gray-500",
    };

    return {
      className: colors[status as keyof typeof colors] || "bg-blue-500",
    };
  };

  const handleSelectSlot = ({ start, end }: { start: Date; end: Date }) => {
    const startMoment = moment(start);
    const endMoment = moment(end);
    const isAllDayRange =
      startMoment.hour() === 0 &&
      startMoment.minute() === 0 &&
      endMoment.hour() === 0 &&
      endMoment.minute() === 0 &&
      endMoment.diff(startMoment, "days") >= 1;
    const adjustedEnd = isAllDayRange ? endMoment.clone().subtract(1, "day") : endMoment;
    const nextStartDate = startMoment.format("YYYY-MM-DD");
    const nextEndDate = adjustedEnd.format("YYYY-MM-DD");

    setSelectedEvent(null);
    setSelectedRange({
      startDate: nextStartDate,
      endDate: nextEndDate === nextStartDate ? nextStartDate : nextEndDate,
    });
    setShowCreateDialog(true);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Tímový kalendár</h1>
        <Button
          className="w-full sm:w-auto"
          onClick={() => {
            setSelectedRange(null);
            setShowCreateDialog(true);
          }}
        >
          <Plus className="mr-2 h-4 w-4" />
          Nová žiadosť
        </Button>
      </div>

      {namedayData?.names?.length ? (
        <Card className="p-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-muted-foreground">
              Dnes meniny: <span className="font-medium text-foreground">{namedayData.names.join(", ")}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {(namedayData.users || []).length === 0 ? (
                <Badge variant="secondary">Nikto z používateľov</Badge>
              ) : (
                namedayData.users.map((user) => (
                  <Badge key={user.id} variant="secondary">
                    {user.name}
                  </Badge>
                ))
              )}
            </div>
          </div>
        </Card>
      ) : null}

      <Card className="p-3 sm:p-6">
        <div className="calendar-container overflow-x-auto">
          <BigCalendar
            localizer={localizer}
            events={calendarEvents}
            startAccessor="start"
            endAccessor="end"
            style={{ height: 600, minWidth: 720 }}
            view={view}
            onView={(nextView: string) => setView(nextView as CalendarView)}
            date={date}
            onNavigate={setDate}
            eventPropGetter={eventStyleGetter}
            onSelectEvent={(event: CalendarEvent) => {
              if (event.resource?.kind === "HOLIDAY" || event.resource?.kind === "BIRTHDAY") {
                return;
              }
              setSelectedEvent(event.resource);
            }}
            selectable
            onSelectSlot={handleSelectSlot}
            messages={{
              allDay: "Celý deň",
              previous: "Späť",
              next: "Ďalej",
              today: "Dnes",
              month: "Mesiac",
              week: "Týždeň",
              day: "Deň",
              agenda: "Agenda",
              date: "Dátum",
              time: "Čas",
              event: "Udalosť",
              noEventsInRange: "Žiadne udalosti v tomto období",
              showMore: (total: number) => `+${total} ďalšie`,
              work_week: "Pracovný týždeň",
            }}
          />
        </div>
      </Card>

      {showCreateDialog && (
        <RequestFormDialog
          open={showCreateDialog}
          onClose={() => setShowCreateDialog(false)}
          initialStartDate={selectedRange?.startDate}
          initialEndDate={selectedRange?.endDate}
        />
      )}

      {selectedEvent && (
        <RequestDetailDialog
          request={selectedEvent}
          open={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
