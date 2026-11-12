import { Inject, Injectable, UnauthorizedException } from '@nestjs/common'

import { ValidatePasswordAction } from '@/api/zstack/ValidatePasswordAction'
import { ActionService } from '@/base/action-service'

@Injectable()
export class ValidatePasswordService extends ActionService {
  @Inject() validatePasswordAction: ValidatePasswordAction

  /**
   * 校验密码是否正确（GraphQL: validatePassword）。
   *
   * 安全要求：必须携带有效会话（x-session-id 且存在于本地 zs_session），
   * 否则抛出 UnauthorizedException。该接口本质是"密码是否正确"的判定器，
   * 未认证开放会变成在线密码爆破预言机（已实测可通过它确认默认口令）。
   */
  async validatePassword(loginName: string, password: string, loginType: string): Promise<boolean> {
    const sessionId = this.getSessionId()
    if (!sessionId) {
      throw new UnauthorizedException('Session not found')
    }

    const session = await this.getZsSession().findOne({
      where: { sessionId }
    })
    if (!session) {
      throw new UnauthorizedException('Invalid session')
    }

    const { available } = await this.validatePasswordAction.call({
      loginName,
      loginType,
      password
    })
    return available
  }
}
