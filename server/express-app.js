import express from 'express';
import cors from 'cors';
import { handleGetData, handleUpdateData } from './api-handlers.js';

const app = express();

app.use(cors());

app.use(express.json({ limit: '2mb' }));
app.post('/api/data', (req, res) => {
    handleGetData(req, res, req.body || {});
});
app.get('/api/data', (req, res) => {
    const action = req.query.action || 'get_public_data';
    handleGetData(req, res, { action });
});
app.post('/api/update', (req, res) => {
    handleUpdateData(req, res, req.body || {});
});

app.get('/', (req, res) => {
    res.send('API Server is running.');
});

export const expressApp = app;
