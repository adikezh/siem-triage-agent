package web

func language(s string) string {
	if s == "ru" {
		return "ru"
	}
	if s == "kk" || s == "kz" {
		return "kk"
	}
	return "en"
}
func (v viewModel) T(key string) string {
	if v.Lang == "ru" {
		if value, ok := ru[key]; ok {
			return value
		}
	}
	if v.Lang == "kk" {
		if value, ok := kk[key]; ok {
			return value
		}
	}
	return key
}

var ru = map[string]string{
	"Navigation": "Навигация", "Source IP": "IP источника", "Suggested actions": "Рекомендуемые действия", "Match": "Условия", "low": "Низкая", "medium": "Средняя", "high": "Высокая", "critical": "Критическая", "drop": "Не уведомлять", "downgrade": "Понизить", "tag": "Пометить",
	"Incidents": "Инциденты", "Dashboard": "Обзор", "Suppressions": "Суппрессии", "Assets": "Активы", "Sign out": "Выйти", "Sign in": "Войти", "API key": "Ключ API", "Invalid API key": "Неверный ключ API", "Read-only access": "Доступ только для чтения", "Demo mode — no API keys configured": "Деморежим — ключи API не настроены", "Authenticate with an issued API key. It is not stored in your browser.": "Войдите с выданным ключом API. Он не сохраняется в браузере.",
	"Analyst workbench": "Рабочее место аналитика", "Severity": "Критичность", "All": "Все", "Since": "Начиная с", "Limit": "Лимит", "Filter": "Применить", "Fingerprint": "Отпечаток", "Score": "Оценка", "Alerts": "События", "Last seen": "Последнее событие", "First seen": "Первое событие", "No incidents yet.": "Инцидентов пока нет.", "Incident": "Инцидент", "Explanation": "Объяснение", "No model explanation available. Review the evidence below.": "Объяснение модели отсутствует. Изучите данные ниже.", "Incident payload": "Данные инцидента", "Analyst verdict": "Вердикт аналитика", "Comment": "Комментарий", "True positive": "Подтверждённая угроза", "False positive": "Ложное срабатывание", "Acknowledge": "Принять в работу", "Feedback history": "История вердиктов", "No feedback yet.": "Вердиктов пока нет.", "Repeated false positives": "Повторные ложные срабатывания", "Review a suppression": "Проверить суппрессию", "New suppression": "Новая суппрессия", "At least one match condition is required. All populated conditions must match.": "Нужно хотя бы одно условие. Все заполненные условия должны совпасть.", "Rule ID": "ID правила", "Source IP / CIDR / glob": "IP источника / CIDR / шаблон", "Agent ID": "ID агента", "Description regex": "Регулярное выражение описания", "Groups, comma separated": "Группы через запятую", "Action": "Действие", "Reason": "Причина", "Expires at (RFC3339, optional)": "Срок действия (RFC3339, необязательно)", "Create suppression": "Создать суппрессию", "Cancel": "Отмена", "Drop": "Не уведомлять", "Downgrade": "Понизить критичность", "Tag": "Пометить", "Expires": "Истекает", "Created by": "Автор", "Delete": "Удалить", "No suppressions.": "Суппрессий нет.", "Hostname": "Имя хоста", "Owner": "Владелец", "Environment": "Среда", "Criticality": "Важность", "Tags": "Метки", "No assets configured.": "Активы не настроены.", "Time range": "Период", "Last 24 hours": "Последние 24 часа", "Last 7 days": "Последние 7 дней", "All time": "Всё время", "Total": "Всего", "Count": "Количество", "Top source IPs": "Источники событий", "MITRE tactics": "Тактики MITRE", "Feedback and delivery — all time": "Вердикты и доставка — всё время", "FP rate": "Доля FP", "MTTA (seconds)": "MTTA (секунды)", "LLM calls / errors": "Вызовы / ошибки LLM", "Outbox pending / sent / failed": "Уведомления: ожидают / доставлены / ошибка", "No data.": "Нет данных.",
}
var kk = map[string]string{
	"Navigation": "Навигация", "Source IP": "Дереккөз IP", "Suggested actions": "Ұсынылған әрекеттер", "Match": "Шарттар", "low": "Төмен", "medium": "Орташа", "high": "Жоғары", "critical": "Сындарлы", "drop": "Хабарламау", "downgrade": "Төмендету", "tag": "Белгілеу",
	"Incidents": "Инциденттер", "Dashboard": "Шолу", "Suppressions": "Басу ережелері", "Assets": "Активтер", "Sign out": "Шығу", "Sign in": "Кіру", "API key": "API кілті", "Invalid API key": "API кілті қате", "Read-only access": "Тек оқу рұқсаты", "Demo mode — no API keys configured": "Демо режимі — API кілттері орнатылмаған", "Authenticate with an issued API key. It is not stored in your browser.": "Берілген API кілтімен кіріңіз. Ол браузерде сақталмайды.",
	"Analyst workbench": "Талдаушының жұмыс орны", "Severity": "Қауіп деңгейі", "All": "Барлығы", "Since": "Бастап", "Limit": "Шектеу", "Filter": "Қолдану", "Fingerprint": "Таңба", "Score": "Баға", "Alerts": "Оқиғалар", "Last seen": "Соңғы оқиға", "First seen": "Алғашқы оқиға", "No incidents yet.": "Инциденттер әлі жоқ.", "Incident": "Инцидент", "Explanation": "Түсіндірме", "No model explanation available. Review the evidence below.": "Модель түсіндірмесі жоқ. Төмендегі деректерді тексеріңіз.", "Incident payload": "Инцидент деректері", "Analyst verdict": "Талдаушы шешімі", "Comment": "Пікір", "True positive": "Расталған қауіп", "False positive": "Жалған іске қосылу", "Acknowledge": "Жұмысқа қабылдау", "Feedback history": "Шешімдер тарихы", "No feedback yet.": "Шешімдер әлі жоқ.", "Repeated false positives": "Қайталанған жалған іске қосылулар", "Review a suppression": "Басу ережесін қарау", "New suppression": "Жаңа басу ережесі", "At least one match condition is required. All populated conditions must match.": "Кемінде бір шарт қажет. Толтырылған барлық шарттар сәйкес келуі тиіс.", "Rule ID": "Ереже ID", "Source IP / CIDR / glob": "Дереккөз IP / CIDR / үлгі", "Agent ID": "Агент ID", "Description regex": "Сипаттаманың тұрақты өрнегі", "Groups, comma separated": "Топтар, үтір арқылы", "Action": "Әрекет", "Reason": "Себеп", "Expires at (RFC3339, optional)": "Аяқталу мерзімі (RFC3339, міндетті емес)", "Create suppression": "Басу ережесін жасау", "Cancel": "Бас тарту", "Drop": "Хабарламау", "Downgrade": "Қауіп деңгейін төмендету", "Tag": "Белгілеу", "Expires": "Аяқталады", "Created by": "Автор", "Delete": "Жою", "No suppressions.": "Басу ережелері жоқ.", "Hostname": "Хост атауы", "Owner": "Иесі", "Environment": "Орта", "Criticality": "Маңыздылық", "Tags": "Белгілер", "No assets configured.": "Активтер орнатылмаған.", "Time range": "Кезең", "Last 24 hours": "Соңғы 24 сағат", "Last 7 days": "Соңғы 7 күн", "All time": "Барлық уақыт", "Total": "Барлығы", "Count": "Саны", "Top source IPs": "Негізгі IP дереккөздері", "MITRE tactics": "MITRE тактикалары", "Feedback and delivery — all time": "Шешімдер мен жеткізу — барлық уақыт", "FP rate": "FP үлесі", "MTTA (seconds)": "MTTA (секунд)", "LLM calls / errors": "LLM шақырулары / қателері", "Outbox pending / sent / failed": "Хабарламалар: күтуде / жеткізілді / қате", "No data.": "Деректер жоқ.",
}
