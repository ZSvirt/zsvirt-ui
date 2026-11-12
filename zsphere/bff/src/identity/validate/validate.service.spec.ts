import { UnauthorizedException } from '@nestjs/common'

import { ValidatePasswordService } from './validate.service'

jest.mock('@nestjs/sequelize', () => ({
  InjectModel: () => () => {},
  InjectConnection: () => () => {},
  InjectDataSource: () => () => {}
}))

jest.mock('@/model/zs-session.model', () => ({
  ZsSession: class ZsSession {}
}))

jest.mock('@/api/zstack/ValidatePasswordAction', () => ({
  ValidatePasswordAction: class ValidatePasswordAction {}
}))

jest.mock('@/common/trans/zs-http-service/zs-http-service.service', () => ({
  ZsHttpService: class ZsHttpService {}
}))

const createService = ({
  sessionRow = null,
  available = true
}: {
  sessionRow?: unknown
  available?: boolean
} = {}) => {
  const service = new ValidatePasswordService()
  const mocks = {
    zsSession: {
      findOne: jest.fn().mockResolvedValue(sessionRow)
    },
    validatePasswordAction: {
      call: jest.fn().mockResolvedValue({ available })
    }
  }

  Object.assign(service as unknown as Record<string, unknown>, mocks, {
    context: { req: { headers: { 'x-session-id': 'session-1' } } }
  })

  return { service, mocks }
}

describe('ValidatePasswordService', () => {
  it('rejects when no session header is present (unauthenticated oracle fix)', async () => {
    const { service, mocks } = createService()
    Object.assign(service as unknown as Record<string, unknown>, {
      context: { req: { headers: {} } }
    })

    const promise = service.validatePassword('admin', 'guess', 'account')

    await expect(promise).rejects.toBeInstanceOf(UnauthorizedException)
    // 与 UIPrivilegeService 等现有鉴权检查保持一致的文案，便于客户端统一处理
    await expect(promise).rejects.toThrow('Session not found')
    expect(mocks.validatePasswordAction.call).not.toHaveBeenCalled()
  })

  it('rejects when the session is not registered locally', async () => {
    const { service, mocks } = createService({ sessionRow: null })

    const promise = service.validatePassword('admin', 'guess', 'account')

    await expect(promise).rejects.toBeInstanceOf(UnauthorizedException)
    await expect(promise).rejects.toThrow('Invalid session')
    expect(mocks.validatePasswordAction.call).not.toHaveBeenCalled()
  })

  it('forwards to the action when the caller is authenticated', async () => {
    const { service, mocks } = createService({ sessionRow: { sessionId: 'session-1' } })

    await expect(service.validatePassword('admin', 'secret', 'account')).resolves.toBe(true)
    expect(mocks.validatePasswordAction.call).toHaveBeenCalledWith({
      loginName: 'admin',
      loginType: 'account',
      password: 'secret'
    })
  })

  it('returns false when the password is wrong', async () => {
    const { service } = createService({ sessionRow: { sessionId: 'session-1' }, available: false })

    await expect(service.validatePassword('admin', 'wrong', 'account')).resolves.toBe(false)
  })
})
