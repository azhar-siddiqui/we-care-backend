import nodemailer from "nodemailer";
import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import {
  SMTP_SERVER_HOST,
  SMTP_PORT,
  SMTP_USER_LOGIN,
  SMTP_PASSWORD,
  FORM_EMAIL,
} from "../config/dotenv.config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const transporter = nodemailer.createTransport({
  host: SMTP_SERVER_HOST,
  port: SMTP_PORT,
  secure: false,
  auth: {
    user: SMTP_USER_LOGIN,
    pass: SMTP_PASSWORD,
  },
});

export const sendOtpEmail = async (email, otp, ownerName = "User") => {
  try {
    const templatePath = path.join(__dirname, "../email/otp-email.ejs");

    const html = await ejs.renderFile(templatePath, {
      otp,
      ownerName,
      // currentDate: new Date().toLocaleDateString("en-US", {
      //   day: "2-digit",
      //   month: "short",
      //   year: "numeric",
      // }),
      // currentYear: new Date().getFullYear(),
      // companyName: "we care",
      // companyAddress: "Address 540, City, State",
      // supportEmail: "support@we-care.com",
      // helpCenterUrl: "https://we-care.com/help",
    });

    const mailOptions = {
      from: FORM_EMAIL,
      to: email,
      subject: "Admin Registration OTP",
      text: `Your OTP for admin registration is: ${otp}. It is valid for 10 minutes.`,
      html,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Error sending OTP email:", error);
    throw new Error("Failed to send OTP email");
  }
};
