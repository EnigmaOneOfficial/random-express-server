import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import axios from "axios";
import https from "https";
import fs from "fs";
import path from "path";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const sslServer = https.createServer(
	{
		key: fs.readFileSync(path.join("localhost+2-key.pem")),
		cert: fs.readFileSync(path.join("localhost+2.pem")),
	},
	app,
);

interface AuthRequest extends Request {
	headers: any;
	user?: string | object; // Adjust according to your user object structure
}

app.post("/auth/github", async (req: Request, res: Response) => {
	const { code, platform } = req.body;
	console.log(platform);

	try {
		const tokenResponse = await axios.post(
			"https://github.com/login/oauth/access_token",
			{
				client_id:
					platform === "web"
						? process.env.GITHUB_WEBCLIENT_ID
						: process.env.GITHUB_MOBILECLIENT_ID,
				client_secret:
					platform === "web"
						? process.env.GITHUB_WEBCLIENT_SECRET
						: process.env.GITHUB_MOBILECLIENT_SECRET,
				code: code,
			},
			{
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
				},
			},
		);

		const tokenData = tokenResponse.data;

		if (tokenData.access_token) {
			const userResponse = await axios.get("https://api.github.com/user", {
				headers: {
					Authorization: `token ${tokenData.access_token}`,
				},
			});
			const userData = userResponse.data;

			res.json({
				success: true,
				data: userData,
				accessToken: jwt.sign(
					userData,
					process.env.ACCESS_TOKEN_SECRET as jwt.Secret,
					{
						expiresIn: "1h",
					},
				),
			});
		} else {
			res.status(400).json({
				success: false,
				message: "Invalid authorization code",
			});
		}
	} catch (error) {
		console.error("Error exchanging auth code for token:", error);
		res.status(500).json({
			success: false,
			message: "Internal server error",
		});
	}
});

const authenticateToken = (
	req: AuthRequest,
	res: Response,
	next: NextFunction,
) => {
	const authHeader = req.headers.authorization;
	const token = authHeader?.split(" ")[1];

	if (token == null) {
		return res.status(401).json({ error: "No token provided" });
	}

	jwt.verify(
		token,
		process.env.ACCESS_TOKEN_SECRET as jwt.Secret,
		(err: any, user: string | object | undefined) => {
			if (err) {
				return res.status(403).json({ error: "Token is not valid" });
			}
			req.user = user;
			next();
		},
	);
};

app.get("/protected", authenticateToken, (req: AuthRequest, res: Response) => {
	res.json({ message: "Welcome to the protected route!" });
});

const PORT = process.env.PORT || 3000;
sslServer.listen(PORT, () => console.log(`Server running on port ${PORT}`));
