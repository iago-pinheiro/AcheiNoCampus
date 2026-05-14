import { MapPin, Calendar, Image as ImageIcon } from 'lucide-react';
import { motion } from 'framer-motion';
import { StatusTag } from './StatusTag';
import './CardItem.css';

export function CardItem({
  title,
  imageUrl,
  location,
  date,
  status = 'pending',
  onClick,
  className = ''
}) {
  return (
    <motion.article
      className={`card ${className}`}
      whileHover={{ y: -4, boxShadow: '0 12px 24px rgba(15, 23, 42, 0.1)' }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
    >
      <div className="card__image-wrap">
        {imageUrl ? (
          <img src={imageUrl} alt={title} className="card__image" loading="lazy" />
        ) : (
          <div className="card__placeholder">
            <ImageIcon size={28} />
          </div>
        )}
        <div className="card__status">
          <StatusTag status={status} />
        </div>
      </div>

      <div className="card__body">
        <h3 className="card__title">{title}</h3>

        <div className="card__meta">
          {location && (
            <span className="card__meta-item">
              <MapPin size={13} />
              {location}
            </span>
          )}
          {date && (
            <span className="card__meta-item">
              <Calendar size={13} />
              {date}
            </span>
          )}
        </div>
      </div>
    </motion.article>
  );
}
