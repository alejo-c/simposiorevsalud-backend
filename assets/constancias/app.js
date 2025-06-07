document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('horiz-cert-btn').addEventListener('click', generate_horiz_cert) 
  document.getElementById('vert-cert-btn').addEventListener('click', generate_vert_cert) 
})

function generate_horiz_cert() {
  fetch(`/api/user/horiz-cet`, {
    method: 'PUT',
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

function generate_vert_cert() {
  fetch(`/api/user/vert-cet`, {
    method: 'PUT',
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
