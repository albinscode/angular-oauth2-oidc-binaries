import { throwError } from 'rxjs';
export class OAuthResourceServerErrorHandler {
}
export class OAuthNoopResourceServerErrorHandler {
    handleError(err) {
        return throwError(err);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9wcm9qZWN0cy9saWIvc3JjL2ludGVyY2VwdG9ycy9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFDQSxPQUFPLEVBQWMsVUFBVSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBRTlDLE1BQU0sT0FBZ0IsK0JBQStCO0NBRXBEO0FBRUQsTUFBTSxPQUFPLG1DQUFtQztJQUU5QyxXQUFXLENBQUMsR0FBc0I7UUFDaEMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDekIsQ0FBQztDQUNGIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFJlc3BvbnNlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgdGhyb3dFcnJvciB9IGZyb20gJ3J4anMnO1xuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB7XG4gIGFic3RyYWN0IGhhbmRsZUVycm9yKGVycjogSHR0cFJlc3BvbnNlPGFueT4pOiBPYnNlcnZhYmxlPGFueT47XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxuICBpbXBsZW1lbnRzIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIge1xuICBoYW5kbGVFcnJvcihlcnI6IEh0dHBSZXNwb25zZTxhbnk+KTogT2JzZXJ2YWJsZTxhbnk+IHtcbiAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xuICB9XG59XG4iXX0=