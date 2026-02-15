import express from 'express';
import cors from 'cors';
import { handleGetData, handleUpdateData } from './api-handlers.js';

const app = express();

// Enable CORS for all routes
app.use(cors());

// API routes
app.use(express.json({ limit: '2mb' }));
app.post('/api/data', (req, res) => {
    handleGetData(req, res, req.body || {});
});
app.post('/api/update', (req, res) => {
    handleUpdateData(req, res, req.body || {});
});

// Simple root message
app.get('/', (req, res) => {
    res.send('API Server is running.');
});

export const expressApp = app;
