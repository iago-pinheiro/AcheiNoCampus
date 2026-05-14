import { CheckCircle2, Search, User, Info } from 'lucide-react';
import { Button } from './Button';

export function ReportItemButton({ onClick, className = '' }) {
  return (
    <Button variant="primary" icon={<CheckCircle2 size={18} />} onClick={onClick} className={className} fullWidth>
      Reportar Item
    </Button>
  );
}

export function CheckFoundItemsButton({ onClick, className = '' }) {
  return (
    <Button variant="success" icon={<Search size={18} />} onClick={onClick} className={className} fullWidth>
      Check Found Items
    </Button>
  );
}

export function InfoReportButton({ onClick, className = '' }) {
  return (
    <Button variant="warning" icon={<Info size={18} />} onClick={onClick} className={className} fullWidth>
      Report Item
    </Button>
  );
}

export function MyProfileButton({ onClick, className = '' }) {
  return (
    <Button variant="primary" icon={<User size={18} />} onClick={onClick} className={className} fullWidth>
      My Profile
    </Button>
  );
}
