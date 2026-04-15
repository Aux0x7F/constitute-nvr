const fs = require("fs");
const os = require("os");
const path = require("path");

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

function defaultAppRoot() {
  const localAppData =
    process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "Programs", "Reolink", "resources", "app");
}

function loadRuntime(appRoot) {
  const merged = {};
  for (const entry of fs.readdirSync(appRoot)) {
    if (!entry.endsWith(".js")) {
      continue;
    }
    const full = path.join(appRoot, entry);
    try {
      const chunk = require(full);
      if (chunk && chunk.modules) {
        Object.assign(merged, chunk.modules);
      }
    } catch (_) {
      // Ignore chunks that require renderer-only globals.
    }
  }

  merged[91188] = (module) => {
    module.exports = {};
  };

  const cache = {};
  function req(id) {
    if (cache[id]) {
      return cache[id].exports;
    }
    if (!merged[id]) {
      throw new Error(`missing module ${id}`);
    }
    const module = { exports: {} };
    cache[id] = module;
    merged[id](module, module.exports, req);
    return module.exports;
  }

  req.d = (exports, definition) => {
    for (const key in definition) {
      if (!Object.prototype.hasOwnProperty.call(exports, key)) {
        Object.defineProperty(exports, key, {
          enumerable: true,
          get: definition[key],
        });
      }
    }
  };
  req.r = (exports) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
  };
  req.n = (module) => {
    const getter =
      module && module.__esModule ? () => module.default : () => module;
    req.d(getter, { a: () => getter });
    return getter;
  };
  req.t = (value) => value;
  req.es = (mod, exports) => Object.assign(exports, mod);
  req.nmd = (module) => module;

  return {
    mergedIds: Object.keys(merged)
      .map((value) => Number(value))
      .sort((left, right) => left - right),
    req,
    device: req(25971).device,
    config: req(61395).config,
    native: req(35490).native,
  };
}

function findModuleExport(req, ids, key) {
  for (const id of ids) {
    try {
      const value = req(id);
      if (
        value &&
        typeof value === "object" &&
        Object.prototype.hasOwnProperty.call(value, key)
      ) {
        return value;
      }
    } catch (_) {
      // Skip modules that cannot load in this runtime shape.
    }
  }
  throw new Error(`unable to locate module export ${key}`);
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`timeout: ${label}`)), ms);
    }),
  ]);
}

function defaultAction() {
  return "getPosition";
}

function normalizeObject(value) {
  return value && typeof value === "object" ? value : null;
}

function normalizeRequest(request) {
  if (!request || typeof request !== "object") {
    throw new Error("request must be an object");
  }
  if (!request.ip || typeof request.ip !== "string") {
    throw new Error("ip is required");
  }
  if (typeof request.password !== "string") {
    throw new Error("password is required");
  }
  const action =
    typeof request.action === "string" && request.action.trim()
      ? request.action.trim()
      : defaultAction();
  return {
    action,
    ip: request.ip.trim(),
    username:
      typeof request.username === "string" && request.username.trim()
        ? request.username.trim()
        : "admin",
    channel:
      Number.isInteger(request.channel) || typeof request.channel === "number"
        ? Math.max(0, Number(request.channel))
        : 0,
    password: request.password,
    ptzPosition: normalizeObject(request.ptzPosition),
    ptzSequence: normalizeSequence(request.ptzSequence),
    waitAfterMs:
      Number.isFinite(request.waitAfterMs) && request.waitAfterMs >= 0
        ? Number(request.waitAfterMs)
        : 1500,
  };
}

function normalizeSequence(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => {
      if (!entry || typeof entry !== "object") {
        return null;
      }
      const ptzPosition = normalizeObject(entry.position || entry.ptzPosition || entry);
      if (!ptzPosition) {
        return null;
      }
      return {
        ptzPosition,
        waitAfterMs:
          Number.isFinite(entry.waitAfterMs) && entry.waitAfterMs >= 0
            ? Number(entry.waitAfterMs)
            : 700,
      };
    })
    .filter(Boolean);
}

async function openDevice(device, request) {
  const handle = await withTimeout(
    device.add({
      iAuthMode: 0,
      port: 9000,
      uidPort: 0,
      name: "",
      host: request.ip,
      uid: "",
      username: request.username,
      password: request.password,
      authCode: "",
    }),
    5000,
    "device.add"
  );
  await withTimeout(device.open(handle), 15000, "device.open");
  return handle;
}

async function closeDevice(device, handle) {
  try {
    if (handle >= 0) {
      await withTimeout(device.close(handle), 5000, "device.close");
    }
  } catch (_) {}
  try {
    if (handle >= 0) {
      await withTimeout(device.remove(handle), 5000, "device.remove");
    }
  } catch (_) {}
}

async function readPosition(config, handle, request) {
  return withTimeout(
    config.getPtzPostion(handle, request.channel),
    10000,
    "config.getPtzPostion"
  );
}

async function setPosition(runtime, handle, request) {
  if (!request.ptzPosition) {
    throw new Error("ptzPosition is required for setPosition");
  }
  const enums = findModuleExport(runtime.req, runtime.mergedIds, "BC_CMD_E");
  const types = findModuleExport(runtime.req, runtime.mergedIds, "BC_PTZ_POS");
  const cmdIdx = runtime.config.constructor.getCmdIndex();
  const ack = await withTimeout(
    runtime.config.channelCmd(
      handle,
      request.channel,
      enums.BC_CMD_E.E_BC_CMD_SET_PTZ_POS,
      runtime.native.BCSDK_RemoteSetPtzPostion,
      20,
      request.ptzPosition,
      types.BC_PTZ_POS,
      cmdIdx
    ),
    15000,
    "native setPtzPosition"
  );
  return { ack, cmdIdx };
}

async function sequencePositions(runtime, handle, request) {
  if (!request.ptzSequence.length) {
    throw new Error("ptzSequence is required for sequencePositions");
  }
  const before = await readPosition(runtime.config, handle, request);
  const steps = [];
  for (const entry of request.ptzSequence) {
    const sequenceRequest = {
      ...request,
      ptzPosition: entry.ptzPosition,
    };
    const setResult = await setPosition(runtime, handle, sequenceRequest);
    if (entry.waitAfterMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, entry.waitAfterMs));
    }
    const observed = await readPosition(runtime.config, handle, request);
    steps.push({
      target: entry.ptzPosition,
      observed,
      waitAfterMs: entry.waitAfterMs,
      ...setResult,
    });
  }
  const after = await readPosition(runtime.config, handle, request);
  return {
    ok: true,
    action: request.action,
    before,
    after,
    steps,
  };
}

async function main() {
  const responsePath = process.argv[2];
  if (!responsePath) {
    throw new Error("response path is required");
  }
  const request = normalizeRequest(JSON.parse(await readStdin()));
  const runtime = loadRuntime(defaultAppRoot());
  const handle = await openDevice(runtime.device, request);

  let result;
  try {
    if (request.action === "getPosition") {
      result = {
        ok: true,
        action: request.action,
        position: await readPosition(runtime.config, handle, request),
      };
    } else if (request.action === "setPosition") {
      const before = await readPosition(runtime.config, handle, request);
      const setResult = await setPosition(runtime, handle, request);
      if (request.waitAfterMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, request.waitAfterMs));
      }
      const after = await readPosition(runtime.config, handle, request);
      result = {
        ok: true,
        action: request.action,
        before,
        target: request.ptzPosition,
        after,
        ...setResult,
      };
    } else if (request.action === "sequencePositions") {
      result = await sequencePositions(runtime, handle, request);
    } else {
      throw new Error(`unsupported action ${request.action}`);
    }
  } finally {
    await closeDevice(runtime.device, handle);
  }

  fs.writeFileSync(responsePath, JSON.stringify(result, null, 2));
}

main().catch((error) => {
  const responsePath = process.argv[2];
  if (responsePath) {
    fs.writeFileSync(
      responsePath,
      JSON.stringify(
        {
          ok: false,
          error: error && error.message ? error.message : String(error),
          stack: error && error.stack ? error.stack : "",
        },
        null,
        2
      )
    );
  } else {
    console.error(error);
  }
  process.exit(1);
});
