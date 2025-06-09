import { Router } from "express";
import {
  loginAdmin,
  logoutAdmin,
  refreshAccessToken,
  registerAdmin,
  verifyAdminOtp,
} from "../controllers/admin.controller.js";
import { authenticateAdmin } from "../middleware/admin-middleware/admin.middleware.js";

const AdminRoutes = Router();

AdminRoutes.post("/admin", registerAdmin)
  .post("/admin/verify-otp", verifyAdminOtp)
  .post("/admin/login", loginAdmin)
  .post("/admin/login/refresh-token", refreshAccessToken)
  .get("/admin/logout", authenticateAdmin, logoutAdmin);

export default AdminRoutes;
