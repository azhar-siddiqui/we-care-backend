import { Router } from "express";
import {
  loginAdmin,
  refreshAccessToken,
  registerAdmin,
  verifyAdminOtp,
} from "../controllers/admin.controller.js";

const AdminRoutes = Router();

AdminRoutes.post("/admin", registerAdmin)
  .post("/admin/verify-otp", verifyAdminOtp)
  .post("/admin/login", loginAdmin)
  .post("/admin/login/refresh-token", refreshAccessToken);

export default AdminRoutes;
