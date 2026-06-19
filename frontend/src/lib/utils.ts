import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTimestamp(ts: string) {
  return new Date(ts).toLocaleString();
}

export function severityColor(severity: string) {
  switch (severity) {
    case "critical": return "text-red-500 bg-red-50 border-red-200";
    case "high": return "text-orange-500 bg-orange-50 border-orange-200";
    case "medium": return "text-yellow-500 bg-yellow-50 border-yellow-200";
    default: return "text-green-500 bg-green-50 border-green-200";
  }
}
