fetch("/api/dashboard/panel/verify/", {
  method: "GET",
  credentials: "include", // 👈 muy importante
  headers: {
    "Content-Type": "application/json"
  }
})
.then(res => {
  if (res.status === 401) {
    window.location.href = "/login.html";
  }
  return res.json();
})
.then(data => {
  console.log("Datos del dashboard:", data);
});
