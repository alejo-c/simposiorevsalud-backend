document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('register-btn').addEventListener('click', register)
  document.getElementById('reload-btn').addEventListener('click', reload)
  document.getElementById('cancel-btn').addEventListener('click', hide_update_modal)
  document.getElementById('update-form').addEventListener('submit', update) 

  document.querySelectorAll('.edit-btn').forEach(btn => {
    btn.addEventListener('click', show_update_modal)
  })
  document.querySelectorAll('.remove-btn').forEach(btn => {
    btn.addEventListener('click', remove)
  })

  document.getElementById('update-form').addEventListener('submit', update) 
  document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('input', () => clear_message())
  })

  list_users()
})

function show_update_modal(event) {
  fetch_user_data(event.target.dataset.id).then(user => {
    document.getElementById('sid-input').value = user.email
    document.getElementById('email-input').value = user.email
    document.getElementById('full-name-input').value = user.full_name
    document.getElementById('id-input').value = user.identification
    document.getElementById('role-select').value = user.role
    document.getElementById('hours-input').value = user.hours
    document.getElementById('attendance-select').value = user.attendance
  })

  document.getElementById('update-modal').classList.remove('hidden')
}

function hide_update_modal() {
  document.getElementById('update-modal').classList.add('hidden')
}

async function fetch_user_data(id) {
  let res = await fetch(`/api/admin/user`, {
    method: 'POST',
    body: id,
    credentials: 'include'
  })

  try {
    if (!res.ok) {
      const error = await res.json()
      return show_error_message(`Error! ${error.message} - ${error.message}`)
    }
    return await res.json();

  } catch (error) {
      show_error_message(error.message)
  }
}

function update(event) {
  let form = event.currentTarget

  const data = {
    id: form.sid_input,
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
    return show_error_message('Contraseña no valida')
  }
  if (data.password != data.repeated_password) {
    return show_error_message('Contraseñas no coinciden')
  }

  // TODO: hash password
  delete data.repeated_password

  fetch(`/api/admin/update`, {
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
}

function remove(event) {
  let user_id = event.target.dataset.id

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

  fetch(`/api/user/delete`, {
    method: 'DELETE',
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

function list_users() {
  fetch_user_list()
  .then(users => {
    if (users.length <= 0) {
      return document.getElementById('user-list').innerHTML = `<tr><td colspan="10">Todavía no hay usuarios</td></tr>`
    }

    users.forEach(user => {
      let {role, hours} = get_role(user)
      let {horiz_cert, vert_cert} = get_certificates(user)

      let assistance = 'Remota'
      if (user.assistance === 'presential') {
          assistance = 'Presencial'
      }

      document.getElementById('user-list').innerHTML += `
        <tr>
          <th>${user.id}</th>
          <td>${user.email}</td>
          <td>${user.full_name}</td>
          <td>${user.identification}</td>
          <td>${role}</td>
          <td>${hours}</td>
          <td>${assistance}</td>
          <td>${horiz_cert}</td>
          <td>${vert_cert}</td>
        </tr>
      `
    }) 
  })
  .catch(error => {
    show_error_message(error.message)
  })
}

function get_role(user) {
  let role

  if (typeof user.role === 'object' && user.role !== null && user.role.hasOwnProperty('speaker')) {
    role = 'Ponente'
    hours = String(user.role.speaker.hours)

  } else if (typeof user.role === 'string') {
    switch (user.role) {
      case 'webmaster':
        role = 'Administrador'
        break;
      case 'staff':
        role = 'organizador'
        break;
      default:
        role = 'attendee'
        break;
    }
    hours = '-'
  }
  return {role, hours}
}

function get_certificates(user) {
  let horiz_cert
  if (!user.cert_generated.horizontal) {
    horiz_cert = 'No'
  }
  horiz_cert += 'Generado <button id="horiz-cert-btn" class="btn">Generar</button>'

  let vert_cert
  if (!user.cert_generated.vertical) {
      vert_cert = 'No'
  }
  vert_cert += 'Generado <button id="horiz-cert-btn" class="btn">Generar</button>'
}

async function fetch_user_list() {
  let res = fetch('/api/admin/users', {
    method: 'POST',
    credentials: 'include'
  })

  try {
    if (!res.ok) {
      const error = await response.json().catch(() => ({ message: `Server error: ${response.status}` }));
      show_error_message(`Error! ${error.message} - ${error.message}`)
    }
    return await res.json();

  } catch (error) {
      show_error_message(error.message)
  }
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

function register() {
  window.location.href = '/admin/register'
}

function reload() {
  window.location.reload()
}

