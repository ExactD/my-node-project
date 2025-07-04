import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Підключення до PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
  ssl: {
    rejectUnauthorized: false // Увага: це небезпечно для продакшена!
  }
});

// Middleware
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
  'http://localhost:3000',
  'https://prep-react-jade.vercel.app'
];

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Дозволити запити без origin (наприклад, Postman) або з дозволених сайтів
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
};

app.use(cors(corsOptions));


// Middleware для перевірки JWT
const authenticateToken = (req: any, res: Response, next: any) => {
  // Спочатку перевіряємо токен в cookies
  let token = req.cookies.token;
  
  // Якщо токена немає в cookies, перевіряємо заголовок Authorization
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7); // Видаляємо "Bearer " з початку
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Токен доступу відсутній' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ error: 'Недійсний токен' });
    }
    req.user = user;
    next();
  });
};

app.post('/create', authenticateToken, async (req: Request, res: Response) => {
  const { user_id, test_id, status } = req.body;

  if (!user_id || !test_id || !status) {
    return res.status(400).json({ error: 'user_id, test_id і status є обовʼязковими' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO user_tests (user_id, test_id, status, started_at)
       VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [user_id, test_id, status]
    );

    res.status(201).json({ message: 'Тест створено', test: result.rows[0] });
  } catch (err) {
    console.error('Помилка при створенні user_test:', err);
    res.status(500).json({ error: 'Помилка створення тесту' });
  }
});

app.put('/update', authenticateToken, async (req: Request, res: Response) => {
  const { user_id, score, status, old_status } = req.body;

  if (
    typeof user_id !== 'number' ||
    typeof score !== 'number' ||
    typeof status !== 'number' ||
    typeof old_status !== 'number'
  ) {
    return res.status(400).json({ error: 'user_id, score, status і old_status є обовʼязковими та повинні бути числами' });
  }

  try {
    const result = await pool.query(
      `UPDATE user_tests
       SET score = $1, status = $2, complated_at = NOW()
       WHERE user_id = $3 AND status = $4
       RETURNING *`,
      [score, status, user_id, old_status]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Не знайдено жодного тесту з відповідним статусом для оновлення' });
    }

    res.json({ message: 'Тест(и) оновлено', updated: result.rows });
  } catch (err) {
    console.error('Помилка при оновленні user_test:', err);
    res.status(500).json({ error: 'Помилка оновлення' });
  }
});

app.post('/all', authenticateToken, async (req: Request, res: Response) => {
  const { user_id } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM user_tests WHERE user_id = $1 ORDER BY started_at DESC',
      [user_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Помилка при отриманні всіх user_tests:', err);
    res.status(500).json({ error: 'Помилка отримання тестів' });
  }
});

app.post('/get', authenticateToken, async (req: Request, res: Response) => {
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).json({ error: 'user_id є обовʼязковим' });
  }

  try {
    const result = await pool.query(
      'SELECT test_id, started_at FROM user_tests WHERE user_id = $1 AND status = 1 ORDER BY started_at DESC LIMIT 1',
      [user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Активний тест не знайдено' });
    }

    res.json({ 
      test_id: result.rows[0].test_id,
      started_at: result.rows[0].started_at,
      status: 1 
    });
  } catch (err) {
    console.error('Помилка при отриманні активного тесту:', err);
    res.status(500).json({ error: 'Помилка отримання активного тесту' });
  }
});

export default app;