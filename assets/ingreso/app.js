const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_=+']).*$/

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('login-form').addEventListener('submit', login) 

  document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('input', () => clear_message())
  })
  test()
})

function login() {
  event.preventDefault()
  let form = event.currentTarget

  const data = {
    email: form.user_email.value,
    password: form.user_password.value,
  }

  if (!regex.test(data.password))) {
    show_error_message('Contraseña no valida')
    return 0
  }

  // TODO: hash password
  delete data.repeated_password
  data.role = 'attendee'
  data.hours = 0

  fetch('/api/login', {
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

function test() {
  document.getElementById('email-input').value = 'test@gmail.com'
  document.getElementById('password-input').value = 'T3stexampl*'
}

function show_error_message(message) {
  document.getElementById('message-span').innerText = message
}

function show_success_message(res) {
  console.log(`Success ${res}`)
}

function clear_message() {
  document.getElementById('message-span').innerText = ''
}


