#!/bin/bash
exec /opt/nodejs/bin/node - "$@" << 'EOF'

// Event polyfill for Node.js environment
if (typeof Event === 'undefined') {
    global.Event = class Event {
        constructor(type, eventInitDict = {}) {
            this.type = type;
            this.bubbles = eventInitDict.bubbles || false;
            this.cancelable = eventInitDict.cancelable || false;
            this.composed = eventInitDict.composed || false;
            this.detail = eventInitDict.detail;
            this.target = null;
            this.currentTarget = null;
            this.eventPhase = 0;
            this.defaultPrevented = false;
            this.timeStamp = Date.now();
        }
        
        preventDefault() {
            this.defaultPrevented = true;
        }
        
        stopPropagation() {}
        stopImmediatePropagation() {}
    };
}

// Execute ReKarel CLI
require('/opt/nodejs/commands.min.cjs');
EOF
