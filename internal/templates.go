package wgxdp

import "fmt"

const verifyFormHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wgxdp - Authorize Device</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; background: #f5f5f5; }
  h1 { color: #333; }
  .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  input[type=text] { width: 100%%; padding: 12px; font-size: 24px; text-align: center; letter-spacing: 4px; border: 2px solid #ddd; border-radius: 4px; box-sizing: border-box; font-family: monospace; }
  .buttons { display: flex; gap: 12px; margin-top: 16px; }
  button { flex: 1; padding: 12px; font-size: 16px; border: none; border-radius: 4px; cursor: pointer; }
  .approve { background: #22c55e; color: white; }
  .approve:hover { background: #16a34a; }
  .deny { background: #ef4444; color: white; }
  .deny:hover { background: #dc2626; }
  p { color: #666; }
</style>
</head>
<body>
<h1>Authorize Device</h1>
<div class="card">
  <p>Enter the code displayed on your device to authorize it to join the network.</p>
  <form method="POST" action="/device/verify">
    <input type="text" name="user_code" value="%s" placeholder="XXXX-XXXX" required>
    <div class="buttons">
      <button type="submit" name="action" value="approve" class="approve">Approve</button>
      <button type="submit" name="action" value="deny" class="deny">Deny</button>
    </div>
  </form>
</div>
</body>
</html>`

func verifyResultHTML(title, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wgxdp - %s</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; background: #f5f5f5; }
  h1 { color: #333; }
  .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  p { color: #666; font-size: 18px; }
</style>
</head>
<body>
<h1>%s</h1>
<div class="card">
  <p>%s</p>
</div>
</body>
</html>`, title, title, message)
}
