# Demo GIF Placeholder

To create a demo animation:

1. Use a screen recording tool (QuickTime, OBS, etc.)
2. Record the following flow:
   - Navigate to registration page
   - Register a new user
   - Login with credentials
   - View dashboard
   - Set up OTP (show QR code)
   - View sessions
   - Logout

3. Convert to GIF using:
   - https://ezgif.com/video-to-gif
   - Or ffmpeg: `ffmpeg -i demo.mov -vf "fps=10,scale=800:-1" demo.gif`

4. Save as `docs/demo.gif`
