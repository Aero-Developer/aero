# Aero website

The static website for Aero, served at **aero.free**. Plain hand-written HTML + one CSS file.
No build step, no JavaScript, no frameworks, no external fonts/CDNs/trackers.

## Files

```
site/
  index.html          Home
  download.html       Download (links to the GitHub release + SHA-256)
  screenshots.html    Screenshots
  faq.html            FAQ / Help
  style.css           Shared retro stylesheet
  assets/
    aero.png          Logo (from the app icon)
    favicon.ico
    screenshots/*.png
```

All links are relative, so the site works when opened locally (double-click `index.html`)
and when served from a web root.

## Preview locally

Just open `index.html` in a browser, or serve the folder:

```sh
# Python (any 3.x)
cd site && python -m http.server 8000
# then visit http://localhost:8000
```

## Deploy to the Debian 13 server (nginx)

1. Copy the folder to the server:

   ```sh
   scp -r site/ user@aero.free:/tmp/aero-site
   ssh user@aero.free 'sudo rm -rf /var/www/aero && sudo mv /tmp/aero-site /var/www/aero'
   ```

2. nginx site config (`/etc/nginx/sites-available/aero.free`):

   ```nginx
   server {
       listen 80;
       listen [::]:80;
       server_name aero.free www.aero.free;

       root /var/www/aero;
       index index.html;

       location / {
           try_files $uri $uri/ =404;
       }

       # long-cache static assets, no-cache HTML so updates show immediately
       location ~* \.(png|ico|css)$ {
           expires 7d;
           add_header Cache-Control "public";
       }
   }
   ```

3. Enable and reload:

   ```sh
   sudo ln -sf /etc/nginx/sites-available/aero.free /etc/nginx/sites-enabled/aero.free
   sudo nginx -t && sudo systemctl reload nginx
   ```

4. (Recommended) HTTPS with certbot once DNS points at the server:

   ```sh
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d aero.free -d www.aero.free
   ```

## Updating

- Bump the version string and download link when a new release ships (`index.html`,
  `download.html`) and update the SHA-256 in `download.html`.
- Drop new screenshots into `assets/screenshots/` and reference them in `screenshots.html`.
