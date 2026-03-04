import { prisma } from "../database/client.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Rota de Cadastro (Register)
export const register = async (req, res) => {
  try {
    const { name, email, ra, password } = req.body;

    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { ra }] },
    });

    if (existingUser) {
      return res.status(400).json({ error: "E-mail ou RA já cadastrados." });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        ra,
        password: hashedPassword,
      },
    });

    const { password: _, ...userWithoutPassword } = newUser;

    return res.status(201).json(userWithoutPassword);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro ao registrar usuário." });
  }
};

// Rota de Login
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Senha incorreta." });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      message: "Login realizado com sucesso",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro ao fazer login." });
  }
};
