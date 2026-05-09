import { MapPin, Calendar, Image as ImageIcon } from 'lucide-react';
import { StatusTag } from './StatusTag';
import './CardItem.css';

/**
 * CardItem Component
 */
export function CardItem({
  title,
  imageUrl,
  location,
  date,
  status = 'pending',
  className = ''
}) {
  return (
    <article className={`card-item ${className}`}>
      <div className="card-item__image-wrapper">
        {imageUrl ? (
          <img src={imageUrl} alt={title} className="card-item__image" />
        ) : (
          <div className="card-item__placeholder-image">
            <ImageIcon size={32} />
          </div>
        )}
      </div>
      
      <div className="card-item__content">
        <div className="card-item__header">
          <h3 className="card-item__title">{title}</h3>
          <StatusTag status={status} />
        </div>
        
        <div className="card-item__details">
          {location && (
            <div className="card-item__detail-row">
              <MapPin size={14} className="card-item__icon" />
              <span>{location}</span>
            </div>
          )}
          {date && (
            <div className="card-item__detail-row">
              <Calendar size={14} className="card-item__icon" />
              <span>{date}</span>
            </div>
          )}
        </div>
      </div>
    </article>
  );
}
