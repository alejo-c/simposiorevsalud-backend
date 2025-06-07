curl -X POST http://localhost:300/api/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "full_name": "Test Example", "password": "testexample", "role": "attendee", "hours": "0", "attendance": "remote"}'
