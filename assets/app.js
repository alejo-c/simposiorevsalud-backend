// async function test() {
//   try {
//     const res = await fetch("/api/test")
//     const data = await res.json()
//     console.log("data:", data)
//     console.log("message:", data.message)
//     document.getElementById("test").textContent = data
//   } catch (error) {
//   console.error("Error:", error)
//   document.getElementById("test").textContent = "Error calling API"
//   }
// }
//
function logout() {
  localStorage.removeItem('jwt');
  document.cookie = 'jwt=; Max-Age=0; path=/; secure'

 fetch('/api/auth/logout', {
   method: 'POST',
   headers: {
     'Authorization': `Bearer ${localStorage.getItem('jwt')}`
   }
 })
}

