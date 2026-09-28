app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: ["'unsafe-eval'"] } } }));
