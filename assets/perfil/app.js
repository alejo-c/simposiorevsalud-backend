const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_=+']).*$/

document.addEventListener('DOMContentLoaded', () => {
  fill()
  // TODO: Add remove user feature
  document.getElementById('register-form').addEventListener('submit', update) 

  document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('input', () => clear_message())
  })
})

function fill(full_name, id) {
  document.getElementById('full-name-input').value = full_name
  document.getElementById('id-input').value = id
}

function update(event) {
  event.preventDefault()
  let form = event.currentTarget

  const data = {
    email: form.user_email.value,
    password: form.user_password.value,
    repeated_password: form.user_repeated_password.value,
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
  delete data.full_name
  delete data.identification

  fetch('/api/user/update', {
    method: 'PUT',
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
  
  // TODO: Reload page
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

