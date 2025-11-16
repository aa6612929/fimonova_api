const form = document.getElementById('verify-form');
const result = document.getElementById('result');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  result.style.display = 'none';
  result.classList.remove('error');
  result.textContent = 'Wird überprüft...';

  const serial = document.getElementById('serial').value.trim();
  const random = document.getElementById('random').value.trim();

  try {
    const res = await fetch('/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serial_number: serial, random_code: random })
    });

    if (res.ok) {
      const data = await res.json();

      result.classList.remove('error');
      result.style.display = 'block';

      result.innerHTML = `
        <strong style="font-size:20px;">✅ Zertifikat gültig</strong><br><br>
        <strong>Name:</strong> ${data.student_name}<br>
        <strong>Kurs:</strong> ${data.certificate}<br>
        <strong>Geburtsdatum:</strong> ${data.birthdate}
      `;
    } else {
      const err = await res.json().catch(()=>({detail: 'Fehler'}));

      result.classList.add('error');
      result.style.display = 'block';
      result.textContent = err.detail || 'Nicht gefunden';
    }

  } catch (e) {
    result.classList.add('error');
    result.style.display = 'block';
    result.textContent = 'Serververbindung fehlgeschlagen';
  }
});
