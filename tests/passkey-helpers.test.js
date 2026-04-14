const { parseDevice } = require('../src/routes/passkey-helpers');

describe('parseDevice (passkey-helpers)', () => {
  function makeReq(headers = {}, ip = '127.0.0.1') {
    return { headers, ip };
  }

  it('returns Chrome for Chrome UA', () => {
    const req = makeReq({ 'user-agent': 'Mozilla/5.0 Chrome/120.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Chrome', ipAddress: '127.0.0.1' });
  });

  it('returns Firefox for Firefox UA', () => {
    const req = makeReq({ 'user-agent': 'Mozilla/5.0 Firefox/121.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Firefox', ipAddress: '127.0.0.1' });
  });

  it('returns Safari for Safari UA (not Chrome)', () => {
    const req = makeReq({ 'user-agent': 'Mozilla/5.0 Safari/17.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Safari', ipAddress: '127.0.0.1' });
  });

  it('excludes Safari when Chrome is present', () => {
    const req = makeReq({ 'user-agent': 'Mozilla/5.0 Chrome/120.0 Safari/17.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Chrome', ipAddress: '127.0.0.1' });
  });

  it('returns Edge for Edge UA', () => {
    const req = makeReq({ 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Edge', ipAddress: '127.0.0.1' });
  });

  it('returns Postman for Postman UA', () => {
    const req = makeReq({ 'user-agent': 'PostmanRuntime/7.34.0' });
    expect(parseDevice(req)).toEqual({ deviceName: 'Postman', ipAddress: '127.0.0.1' });
  });

  it('falls back to UA prefix for unknown UAs', () => {
    const req = makeReq({ 'user-agent': 'MyApp/1.0 CustomAgent/2.0' });
    expect(parseDevice(req).deviceName).toBe('MyApp/1.0 CustomAgent/2.0');
  });

  it('defaults to "Unknown Device" when no UA is provided', () => {
    const req = makeReq({});
    expect(parseDevice(req)).toEqual({ deviceName: 'Unknown Device', ipAddress: '127.0.0.1' });
  });

  it('uses req.connection.remoteAddress when req.ip is absent', () => {
    const req = { headers: {}, ip: undefined, connection: { remoteAddress: '10.0.0.1' } };
    expect(parseDevice(req).ipAddress).toBe('10.0.0.1');
  });

  it('defaults ipAddress to 0.0.0.0 when neither req.ip nor remoteAddress is available', () => {
    const req = { headers: {}, ip: undefined, connection: { remoteAddress: undefined } };
    expect(parseDevice(req).ipAddress).toBe('0.0.0.0');
  });
});

