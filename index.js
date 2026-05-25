module.exports = function (app) {
  const plugin = {
    id: 'signalk-ssl',
    name: 'SignalK SSL',
    description: 'SSL/TLS certificate management plugin for SignalK (skeleton).',
    schema: {
      type: 'object',
      properties: {}
    },
    start: function (_options) {
      app.debug('signalk-ssl start (skeleton — no SSL logic implemented)');
    },
    stop: function () {
      app.debug('signalk-ssl stop');
    }
  };

  return plugin;
};
