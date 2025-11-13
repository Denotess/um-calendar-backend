# UM Calendar - Combined Deployment

This repository combines the **Calendar API (C#)** and **Calendar Scraper (Python)** in a single deployment-ready package for Azure.

## 🏗️ Project Structure

```
um-calendar-app/
├── Program.cs              # ASP.NET Core API entry point
├── appsettings.json        # API configuration
├── calendars/              # ✅ Served by API (committed to Git)
│   └── *.ics              # Calendar files
├── scraper/                # Python scraper
│   ├── getFiles.py        # Downloads calendars
│   ├── getLinks.py        # Fetches calendar names
│   └── requirements.txt   # Python dependencies
└── .github/
    └── workflows/
        └── update-calendars.yml  # Auto-updates calendars daily
```

## 📋 What This Repo Does

### 1. API (C# / ASP.NET Core)
- Serves `.ics` calendar files via REST API
- JWT token authentication
- Endpoints:
  - `GET /names` - List all calendars
  - `GET /cal/{name}` - Get specific calendar
  - `GET /generate-token/` - Generate JWT token (requires API key)

### 2. Scraper (Python)
- Downloads calendars from UM FOV website
- Runs automatically via GitHub Actions
- Updates daily at 3 AM UTC
- Saves to `calendars/` folder

### 3. GitHub Actions Automation
- Scraper runs on schedule
- Commits updated calendars
- Triggers Azure deployment
- Zero manual intervention needed!

## 🚀 Deployment

### Azure Configuration

**Environment Variables (set in Azure App Service → Configuration):**

```
Jwt__Key=<your-jwt-signing-key>
Jwt__ApiKey=<your-api-key>
Jwt__Issuer=calendar-api
Jwt__Audience=calendar-api-users
```

**Note:** Use double underscores `__` for nested configuration in Azure.

### GitHub Actions Setup

The workflow runs automatically:
- **Schedule:** Daily at 3 AM UTC
- **Manual trigger:** Available in GitHub Actions tab
- **Auto-deploys:** When calendars update

**No additional setup needed** - just push to GitHub and connect to Azure!

## 🔧 Local Development

### Prerequisites
- .NET 9.0 SDK
- Python 3.11+
- Node.js (if running Vue frontend)

### Setup

**1. Clone the repository**
```bash
git clone https://github.com/Denotess/um-calendar-app.git
cd um-calendar-app
```

**2. Set up environment variables**

Create `.env` file:
```env
Jwt__Key=your-dev-jwt-key
Jwt__ApiKey=your-dev-api-key
Jwt__Issuer=calendar-api
Jwt__Audience=calendar-api-users
```

**3. Run the API**
```bash
dotnet restore
dotnet run
```

API starts at `http://localhost:5000`

**4. Run the scraper (optional)**
```bash
cd scraper
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python getFiles.py
```

## 📡 API Usage

### Generate Token

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  https://your-app.azurewebsites.net/generate-token/
```

### Get Calendar Names

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://your-app.azurewebsites.net/names
```

### Get Specific Calendar

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://your-app.azurewebsites.net/cal/01---1-letnik-VS-Informacijski-sistemi-Redni
```

## 🔒 Security

- `.env` files are gitignored (never committed)
- JWT tokens expire after 1 year
- API key required for token generation
- Calendars are public but require authentication

## 🤖 Automation Details

### How GitHub Actions Works

1. **Trigger:** Runs daily at 3 AM UTC (or manually)
2. **Checkout:** Gets latest code
3. **Setup:** Installs Python and dependencies
4. **Scrape:** Runs `getFiles.py` to download calendars
5. **Check:** Detects if any calendars changed
6. **Commit:** If changed, commits to `calendars/`
7. **Push:** Triggers Azure auto-deployment

### Manual Trigger

Go to GitHub → Actions → "Update Calendars" → Run workflow

## 📁 Important Files

| File | Purpose |
|------|---------|
| `Program.cs` | API application code |
| `calendars/*.ics` | Calendar files (committed) |
| `scraper/getFiles.py` | Download script |
| `.github/workflows/update-calendars.yml` | Automation |
| `.env` | Local secrets (NOT committed) |
| `.gitignore` | Prevents sensitive files from being committed |

## ⚠️ Important Notes

### Calendars Folder
- **Root `calendars/`** → Committed to Git, deployed to Azure
- **`scraper/calendars/`** → Gitignored, local scraper output

The scraper saves to `../calendars/` (root folder) so changes get committed by GitHub Actions.

### Why Combined Repo?
- Simpler deployment (one Azure app)
- GitHub Actions can access both API and scraper
- Easier maintenance
- Lower costs (single App Service)

## 🛠️ Technologies

- **Backend:** ASP.NET Core 9.0 (C#)
- **Scraper:** Python 3.11 (BeautifulSoup4, Requests)
- **Authentication:** JWT Bearer tokens
- **Automation:** GitHub Actions
- **Hosting:** Azure App Service (Linux)
- **CI/CD:** GitHub → Azure auto-deployment

## 📝 Related Repositories

- Original API: [um-calendar-api-cs](https://github.com/Denotess/um-calendar-api-cs)
- Original Scraper: [um-calendar-scraper](https://github.com/Denotess/um-calendar-scraper)
- Frontend: [um-calendar-app](https://github.com/Denotess/um-calendar-app) (Vue.js)

## 📄 License

Free to use for educational purposes.

---

**🎓 University of Maribor - Faculty of Organizational Sciences**

Automated calendar service for students and staff.
