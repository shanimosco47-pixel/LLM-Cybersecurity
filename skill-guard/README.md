<div dir="rtl">

# Skill Guard

שומר אוטומטי לסקילים של Claude במחשב Windows. בודק כל סקיל לפני ההתקנה, וסורק פעם ביום את כל מה שכבר מותקן. חינמי לגמרי, רץ מקומית, ושום מידע לא יוצא מהמחשב.

מנוע הסריקה הוא [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) של Cisco AI Defense: קוד פתוח ברישיון Apache 2.0. הוא מזהה prompt injection, הוצאת מידע (exfiltration) וקוד זדוני. Skill Guard משתמש רק בשלבים המקומיים שלו: חוקי YARA ו־Regex, וניתוח התנהגותי של זרימת נתונים. אין בו שלב LLM, ולכן לא צריך מפתח API.

## מה הוא עושה

| מתי | מה קורה | איפה |
|---|---|---|
| Claude כותב או עורך קובץ בתוך סקיל | הסקיל נסרק **לפני** שהשינוי נשמר. אם נמצאה בעיה, הכתיבה נחסמת. | Claude Code, hook מסוג `PreToolUse` |
| אחרי כל פקודה שClaude מריץ (`git clone`, `npx skills add`, פריסת ZIP) | כל סקיל חדש או שהשתנה נסרק. סקיל מסוכן מועבר להסגר, וClaude מקבל הודעה שעליו לדווח לך. | Claude Code, hook מסוג `PostToolUse` |
| פתיחת סשן חדש | אותה בדיקה, כדי לתפוס התקנות שנעשו מחוץ לClaude, כמו `/plugin install` או העתקה ידנית. | Claude Code, hook מסוג `SessionStart` |
| כל יום ב־09:00 | סריקה מלאה של הכול מחדש, גם של מה שכבר נבדק. כך חוקי זיהוי חדשים תופסים גם סקילים ישנים. לפני הסריקה הסורק מתעדכן. | משימה מתוזמנת `SkillGuard-Daily` |
| קובץ ZIP נכנס לתיקיית השער | נסרק, ומועבר ל־`approved` או ל־`rejected` עם דוח. | משימה מתוזמנת `SkillGuard-Gate` |

בנוסף, ההתקנה מוסיפה חוקי deny לקובץ ההגדרות של Claude Code. הם חוסמים קריאה של קבצים רגישים (`~/.ssh`, `~/.aws`, `.env` ועוד), ומונעים מClaude לערוך את Skill Guard עצמו ואת קובץ ההגדרות. זה קו ההגנה האחרון, למקרה שסקיל זדוני עבר את הסריקה.

## התקנה

דרישה: Python בגרסה 3.11 עד 3.14. אם אין לך, אפשר להתקין עם `winget install Python.Python.3.13`.

ב־PowerShell, מתוך התיקייה `skill-guard`:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

לא צריך הרשאות מנהל. בסיום, צריך לסגור ולפתוח מחדש סשנים פתוחים של Claude Code.

אפשרויות:
- `-DailyAt "20:00"`: שעה אחרת לסריקה היומית
- `-NoDenyRules`: בלי חוקי ה־deny

## עבודה עם claude.ai (דפדפן ואפליקציה)

ב־claude.ai אין hooks, ולכן ההגנה שם תלויה בהרגל אחד: **כל סקיל עובר דרך תיקיית השער לפני ההעלאה.**

1. שומרים את קובץ ה־ZIP של הסקיל בתיקייה `%USERPROFILE%\SkillGate\inbox`.
2. תוך כמה שניות מופיעה התראה, והקובץ עובר לאחת משתי תיקיות:
   - `approved`: אפשר להעלות ל־claude.ai.
   - `rejected`: לא להעלות. ליד הקובץ יש דוח `.report.txt` שמפרט מה נמצא.
3. התיקייה `approved` משמשת כארכיון של כל מה שהעלית. הסריקה היומית עוברת גם עליה. אם סקיל שאושר בעבר מסומן פתאום כמסוכן, הוא עובר ל־`rejected` ותקבל התראה **למחוק אותו מ־claude.ai**.

## פקודות שימושיות

```powershell
$g = "$env:USERPROFILE\.skill-guard"
& "$g\venv\Scripts\python.exe" "$g\guard.py" status          # מה נסרק ומה בהסגר
& "$g\venv\Scripts\python.exe" "$g\guard.py" scan-all        # סריקה מלאה עכשיו
& "$g\venv\Scripts\python.exe" "$g\guard.py" restore <שם>    # החזרה מהסגר (התראת שווא)
```

- יומן: `%USERPROFILE%\.skill-guard\guard.log`
- דוחות סריקה מלאים בפורמט JSON: `%USERPROFILE%\.skill-guard\reports`
- הסגר: `%USERPROFILE%\.skill-guard\quarantine`. שום דבר לא נמחק, הקבצים רק מועברים.

סקיל שהוחזר מההסגר ידנית נחשב מאושר כל עוד הוא לא משתנה. כל שינוי בו ייסרק מחדש.

הסרה: `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`. מוסיפים `-DeleteData` כדי למחוק גם יומנים והסגר.

## הגדרות

הקובץ `%USERPROFILE%\.skill-guard\config.json` הוא אופציונלי. אלה ברירות המחדל:

```json
{
  "block_severity": "HIGH",
  "use_behavioral": true,
  "auto_update_scanner": true,
  "notify": true,
  "gate_dir": "C:\\Users\\<you>\\SkillGate"
}
```

- `block_severity`: מאיזו רמת חומרה לחסום. הערכים האפשריים: `MEDIUM`, `HIGH`, `CRITICAL`.
- `auto_update_scanner`: האם לעדכן את הסורק מ־PyPI בכל יום. היתרון: חוקי זיהוי עדכניים. החיסרון: תלות בשרשרת האספקה של PyPI. אם תכבה את העדכון, הקפד לעדכן ידנית מדי פעם.

## מגבלות (חשוב לקרוא)

- **סריקה נקייה לא מבטיחה סקיל נקי.** גם Cisco מציינים את זה בתיעוד שלהם. מתקפה שמנוסחת בשפה טבעית חכמה יכולה לעבור חוקי זיהוי. לסקיל ממקור לא מוכר, תקרא גם את `SKILL.md` בעצמך.
- **חוקי deny הם לא sandbox.** Claude עדיין יכול להריץ פקודות shell. אם צריך גבול קשיח, צריך בידוד ברמת מערכת ההפעלה, כמו devcontainer או מכונה וירטואלית.
- **claude.ai תלוי בהרגל.** סקיל שמעלים ישירות, בלי לעבור בתיקיית השער, לא נבדק.
- **התקנה שClaude לא מבצע** (למשל `/plugin install`) נתפסת רק בפתיחת הסשן הבא, לא באותו רגע.
- **רק Claude Code ותיקיית השער מכוסים.** תיקיות של Cursor או Codex לא נסרקות.
- **אם הסורק נכשל:** ב־hook של לפני הכתיבה תופיע שאלת אישור. בבדיקה שאחרי הפעולה תופיע אזהרה, אבל הסקיל לא יועבר להסגר.

## בדיקות

```bash
python -m unittest discover -s skill-guard/tests -v
```

את הבדיקות מריצים עם ה־Python שבו מותקן `cisco-ai-skill-scanner`. הן מריצות את הסורק האמיתי על סקילים זדוניים ונקיים בתיקיית בית זמנית.

</div>
