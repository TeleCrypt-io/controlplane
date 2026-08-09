async function command(url, o = {}) {
  o.headers = Object.assign({}, o.headers, { "X-TeleCrypt-Request-ID": crypto.randomUUID() });
  return fetch(url, o);
}

async function createTeam() {
  const r = await command("/api/team", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function addSeat(e) {
  e.preventDefault();
  const r = await command("/api/team/seats", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mxid: e.target.mxid.value.trim() }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

async function removeSeat(mxid) {
  const r = await command("/api/team/seats/" + encodeURIComponent(mxid), { method: "DELETE" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function checkout(e) {
  e.preventDefault();
  const r = await command("/api/team/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (!r.ok) { alert(await r.text()); return false; }
  location = (await r.json()).payment_link;
  return false;
}

async function openPortal() {
  const r = await command("/api/team/portal", { method: "POST" });
  if (r.ok) window.open((await r.json()).link, "_blank"); else alert(await r.text());
}

async function changeSeatCount(e) {
  e.preventDefault();
  const r = await command("/api/team/seat-count", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}
