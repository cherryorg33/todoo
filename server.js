const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
// const { User, Task } = require('./models');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());
const sequelize = new Sequelize('todolist_db', 'username', 'password', {
    dialect: 'mysql',
    host: 'localhost',
  });
  
  // Define User model
  const User = sequelize.define('User', {
    username: { type: Sequelize.STRING, unique: true },
    password: Sequelize.STRING,
  });
  
  // Define Task model
  const Task = sequelize.define('Task', {
    description: Sequelize.STRING,
    status: Sequelize.BOOLEAN,
    dueDate: Sequelize.DATE,
  });
  
  // Define the foreign key relationship
  User.hasMany(Task);
  Task.belongsTo(User);

// JWT Secret Key (Change this to a strong, random secret in production)
const secretKey = 'your-secret-key';

// Middleware to verify JWT
function authenticateJWT(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
}

// Routes

// User registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({ username, email, password: hashedPassword });

    res.status(201).json({ userId: user.id, username: user.username });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// User login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) return res.status(400).json({ error: 'Invalid email or password.' });

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ userId: user.id }, secretKey);
    res.json({ token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Tasks CRUD

// Create a task
app.post('/tasks', authenticateJWT, async (req, res) => {
  const { description, status, dueDate } = req.body;

  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const task = await Task.create({ description, status, dueDate });
    await user.addTask(task);

    res.status(201).json(task);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Read all tasks of the authenticated user
app.get('/tasks', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId, { include: Task });
    if (!user) return res.status(404).json({ error: 'User not found.' });

    res.json(user.Tasks);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update a task by ID
app.put('/tasks/:id', authenticateJWT, async (req, res) => {
  const taskId = req.params.id;
  const { description, status, dueDate } = req.body;

  try {
    const task = await Task.findByPk(taskId);
    if (!task) return res.status(404).json({ error: 'Task not found.' });

    await task.update({ description, status, dueDate });

    res.json(task);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete a task by ID
app.delete('/tasks/:id', authenticateJWT, async (req, res) => {
  const taskId = req.params.id;

  try {
    const task = await Task.findByPk(taskId);
    if (!task) return res.status(404).json({ error: 'Task not found.' });

    await task.destroy();

    res.json({ message: 'Task deleted.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
