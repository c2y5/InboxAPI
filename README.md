# InboxAPI 📬

**InboxAPI** is a lightweight email testing API that generates namespaces and captures emails for integration testing.

[Try it out yourself here!](https://inbox.aesis.xyz/)

---

![Banner](./InboxAPIBanner.png)

---

## Installation 📦

1. Clone the repository:

   ```bash
   git clone https://github.com/c2y5/InboxAPI.git
   cd InboxAPI
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Setup ``.env``
   
   ```
   MONGO_URI=
   SECRET_KEY=
   JWT_SECRET_KEY=
   ```

4. In Cloudflare worker create a worker, edit the domain urls in ./worker.js (line 7 & 47) and deploy it

5. In the Email tab -> routing rules -> catch-all -> set it to send to worker

---

## Usage 🚀

Run the app locally:

```bash
python app.py
```

Open your browser at `http://localhost:5000`.

---

## License 📄

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## Contributing 🤝

Feel free to submit issues or pull requests! Suggestions to improve InboxAPI are very welcome.

---


