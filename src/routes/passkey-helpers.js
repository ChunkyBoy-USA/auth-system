// Shared device parsing for passkey routes
function parseDevice(req) {
  const ua = req.headers['user-agent'] || 'Unknown Device';
  let deviceName = 'Unknown Device';
  if (ua.includes('Chrome')) deviceName = 'Chrome';
  else if (ua.includes('Firefox')) deviceName = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) deviceName = 'Safari';
  else if (ua.includes('Edge')) deviceName = 'Edge';
  else if (ua.includes('Postman')) deviceName = 'Postman';
  else deviceName = ua.slice(0, 40);
  return {
    deviceName,
    ipAddress: req.ip || req.connection.remoteAddress || '0.0.0.0',
  };
}

module.exports = { parseDevice };
