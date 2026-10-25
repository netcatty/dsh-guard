// dsh-guard/mask — agent-scope tool masking.
//
// Mount this row INSIDE an agent preset (its ctx is the agent scope). It calls
// ctx.tools.restrict, which is the only way to hide tools from one agent;
// a profile-root plugin cannot reach that scope.
//
// Example preset row:
//   - id: guard-mask
//     name: dsh-guard/mask
//     config: { denyTools: [write, edit] }

export const name = 'guard-mask';

export function apply(ctx, config = {}) {
  const deny = Array.isArray(config.denyTools) ? config.denyTools : ['write', 'edit'];
  if (deny.length === 0) return;
  try {
    ctx.tools.restrict({ deny });
  } catch (error) {
    ctx.logger?.warn?.(`dsh-guard/mask: restrict failed: ${String(error)}`);
  }
}
