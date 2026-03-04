# PurePath AI – Backend API

**Team 23 | Capstone | Women Techsters Fellowship**

A secure REST API backend for the PurePath AI waste management platform.

## Quick Start

```bash
npm install
cp .env.example .env     # Fill in your secrets
npm run dev              # Development server (http://localhost:5000)
npm test                 # Run security test suite
```

## API Endpoints

### Public Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/reports` | List all reports (supports `?status=`, `?waste_category=`, `?limit=`, `?offset=`) |
| GET | `/api/reports/:id` | Get single report |
| POST | `/api/reports` | Submit new waste report (with image upload) |
| GET | `/api/reports/hotspots` | Get hotspot clusters |
| POST | `/api/auth/login` | Admin login → returns JWT token |

### Protected Endpoints (JWT required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/profile` | Current user info |
| PATCH | `/api/reports/:id/status` | Update cleanup status |
| GET | `/api/reports/admin/stats` | Dashboard statistics |

## Submitting a Report (Example)

```bash
curl -X POST http://localhost:5000/api/reports \
  -F "latitude=5.6037" \
  -F "longitude=-0.1870" \
  -F "waste_category=plastic" \
  -F "confidence_score=0.92" \
  -F "description=Large plastic dump near canal entrance" \
  -F "image=@/path/to/photo.jpg"
```

## Admin Login (Example)

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourPassword"}'
```

Use the returned token in subsequent requests:
```bash
curl -X PATCH http://localhost:5000/api/reports/<id>/status \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"status":"in_progress"}'
```

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the full security documentation including:
- Threat assessment (STRIDE model)
- Secure API configuration details
- Data protection measures
- Security testing guide and checklist
