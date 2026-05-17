# constitute-nvr

`constitute-nvr` is the native camera and media service for Constitution.

It owns camera discovery, camera-device management, media planning, recording
workers, camera inventory/media projections, and live preview admission for
browser surfaces. Live preview/control runs through CAAC-opened,
route-promised swarm stream records and emits admission, answer, route-plan,
state, and projection records; media bytes stay outside control records.
