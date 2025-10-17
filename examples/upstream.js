import * as http from "http";
import Express from "express";

const app = Express();
app.get("/", (req, res) => {
    console.log(req.headers);
    const header = req.headers['x-client-tls-info'];
    if (header) {
        const info = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
        res.send(`Client Subject: ${info.subject}`);
    } else {
        res.status(401).send('Unauthorized');
    }
})

const server = http.createServer(app);
server.listen(8080);
