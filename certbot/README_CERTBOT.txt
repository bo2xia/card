This folder is reserved for future Certbot integration.

Option A: Use system certbot on host
1. Stop nginx container: docker-compose -f docker-compose.prod.yml stop nginx
2. Run certbot standalone on host:
   sudo certbot certonly --standalone -d km.videox.xyz -d www.km.videox.xyz
3. Copy certificates to project ssl/:
   sudo cp /etc/letsencrypt/live/km.videox.xyz/fullchain.pem ssl/cert.pem
   sudo cp /etc/letsencrypt/live/km.videox.xyz/privkey.pem ssl/key.pem
4. Start nginx: docker-compose -f docker-compose.prod.yml up -d nginx

Option B: Use certbot docker (not included yet)
- You can add a certbot container that writes to a shared /var/www/certbot volume
- Then run certbot renew via cron or docker scheduled jobs

After copying certs, restart prod stack:
  docker-compose -f docker-compose.prod.yml restart
