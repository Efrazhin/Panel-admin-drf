document.getElementById("login-form").addEventListener("submit", async function (e) {
  e.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const errorDiv = document.getElementById("error-message");
  errorDiv.textContent = "";

  try {
    const response = await fetch("/api/users/login/", {
      method: "POST",
      credentials: "include", // importante para cookies
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });

    if (response.ok) {
      window.location.href = "/api/dashboard/panel-data/"; // redirige si es exitoso
    } else {
      const data = await response.json();
      errorDiv.textContent = data.non_field_errors || "Error al iniciar sesión";
    }
  } catch (error) {
    console.error("Error de red:", error);
    errorDiv.textContent = "Error de red. Intenta nuevamente.";
  }
});
