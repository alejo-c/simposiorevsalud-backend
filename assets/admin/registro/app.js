const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_=+']).*$/

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('register-form').addEventListener('submit', register) 

  document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('input', () => clear_message())
  })
  test()
})

function register(event) {
  event.preventDefault()
  let form = event.currentTarget

  const data = {
    email: form.user_email.value,
    full_name: form.user_full_name.value,
    identification: form.user_id.value,
    password: form.user_password.value,
    repeated_password: form.user_repeated_password.value,
    role: form.user_role.value,
    hours: form.user_hours.value || 0,
    attendance: form.user_attendance.value
  }

  if (!regex.test(data.password) || !regex.test(data.repeated_password)) {
    show_error_message('Contraseña no valida')
    return 0
  }

  if (data.password != data.repeated_password) {
    show_error_message('Contraseñas no coinciden')
    return 0
  }

  // TODO: hash password
  delete data.repeated_password

  fetch('/api/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data),
    credentials: 'include'
  })
  .then(response => {
    if (!response.ok) {
      return response.text().then(text => {
        throw new Error(text)
      })
    }
    return response.text()
  })
  .then(text => {
    show_success_message(text)
  })
  .catch(error => {
    show_error_message(error.message)
  })
}

function show_error_message(message) {
  document.getElementById('message-span').innerText = message
}

function show_success_message(res) {
  console.log(`Success ${res}`)
}

function test() {
  document.getElementById('email-input').value = 'test@gmail.com'
  document.getElementById('full-name-input').value = 'Test Example'
  document.getElementById('id-input').value = '1234567890'
  document.getElementById('password-input').value = 'T3stexampl*'
  document.getElementById('repeat-password-input').value = 'T3stexampl*'
  document.getElementById('role-select').value = 'attendee'
  document.getElementById('hours-input').value = 2
  document.getElementById('attendance-select').value = 'remote'
}

function clear_message() {
  document.getElementById('message-span').innerText = ''
}

