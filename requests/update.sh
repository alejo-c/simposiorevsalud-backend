curl -X http://localhost:3000/api/update \
  -H "Cookie: token=" \
  -H "Content-Type: application/json" \
  -d '{"id": "", "email": "test2@example.com", "full_name": "Test Example New", "password": "testexample2", "role": "speaker", "hours": "2", "attendance": "presential"}'
