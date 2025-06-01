import crypto from "crypto";

export const generateOtp = () => {
  // Generate a random number between 10000 and 99999
  const min = 10000;
  const max = 99999;
  const randomBytes = crypto.randomInt(min, max + 1); // randomInt generates an integer in [min, max]
  return randomBytes.toString();
};
