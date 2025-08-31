import PostalMime from "postal-mime";

export default {
  async email(message, env, ctx) {
    const [localPart, domain] = message.to.split("@");

    if (domain !== "example.com") {  
      return;
    }

    const [namespace, tag] = localPart.split(".");

    const parser = new PostalMime();
    const parsedEmail = await parser.parse(message.raw);

    const subject = parsedEmail.subject;
    const text = parsedEmail.text;
    const html = parsedEmail.html;

    const attachments = (parsedEmail.attachments || []).map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      size: att.content.length,
      content: btoa(
        String.fromCharCode(...new Uint8Array(att.content))
      )
    }));

    const payload = {
      to: message.to,
      from: message.from,
      subject,
      text,
      html,
      attachments,
      tag,
      id: message.id || `${Date.now()}-${namespace}-${tag}`,
      envelope_from: message.from,
      envelope_to: message.to,
      from_parsed: message.from_parsed || [{ address: message.from, name: "" }],
      cc: message.cc,
      cc_parsed: message.cc_parsed,
      dkim: message.dkim,
      SPF: message.SPF
    };

    let url = "https://example.com/internal/receive_mail/" + namespace;

    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  }
};
