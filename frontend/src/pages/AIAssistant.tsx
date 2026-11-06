import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  Loader2,
  MessageSquare,
  Trash2,
  Plus,
  AlertCircle,
  User,
  Sparkles,
  Clock,
  Hash,
  ArrowLeft
} from 'lucide-react';

import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';

import {
  aiService,
  AIConversation,
  AIChatResponse,
  AIMessage,
  AIUsageStats
} from '../services/aiService';

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) return error.message;
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') {
    return error.message;
  }
  return fallback;
}

export const AIAssistantPage: React.FC = () => {
  const [conversations, setConversations] = useState<AIConversation[]>([]);
  const [currentConversation, setCurrentConversation] = useState<AIConversation | null>(null);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [usageStats, setUsageStats] = useState<AIUsageStats | null>(null);
  const [suggestions] = useState<string[]>([
    '如何配置系统邮件通知？',
    '推荐的日期时间格式是什么？',
    '如何设置多语言支持？',
    '系统性能优化建议？',
    '如何备份系统配置？'
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const activeSessionIdRef = useRef<string | null>(null);
  const conversationOperationRef = useRef(0);
  const conversationListRequestRef = useRef(0);
  const conversationDeleteRequestRef = useRef(0);
  const sendRequestRef = useRef(0);
  const activeSendRef = useRef(false);

  useEffect(() => {
    loadConversations();
    loadUsageStats();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadConversations = async () => {
    const requestId = ++conversationListRequestRef.current;
    try {
      const response = await aiService.getConversations(1, 10);
      if (requestId === conversationListRequestRef.current) setConversations(response.items || []);
    } catch (error: unknown) {
      if (requestId !== conversationListRequestRef.current) return;
      setError(getErrorMessage(error, '加载对话列表失败'));
      setConversations([]);
    }
  };

  const loadUsageStats = async () => {
    try {
      const stats = await aiService.getUsageStats();
      setUsageStats(stats);
    } catch (error: unknown) {
      console.error('加载使用统计失败:', error);
    }
  };

  const startNewConversation = async () => {
    const operationId = ++conversationOperationRef.current;
    ++sendRequestRef.current;
    activeSendRef.current = false;
    activeSessionIdRef.current = null;
    setCurrentConversation(null);
    setMessages([]);
    setError('');
    setSending(false);

    try {
      setLoading(true);
      const conversation = await aiService.startConversation('新对话');
      if (operationId !== conversationOperationRef.current) return;
      activeSessionIdRef.current = conversation.session_id;
      setCurrentConversation(conversation);
      setMessages([]);
      await loadConversations();
    } catch (error: unknown) {
      if (operationId === conversationOperationRef.current) {
        setError(getErrorMessage(error, '创建对话失败'));
      }
    } finally {
      if (operationId === conversationOperationRef.current) setLoading(false);
    }
  };

  const selectConversation = (conversation: AIConversation) => {
    ++conversationOperationRef.current;
    ++sendRequestRef.current;
    activeSendRef.current = false;
    activeSessionIdRef.current = conversation.session_id;
    setCurrentConversation(conversation);
    const parsedMessages = aiService.parseMessages(conversation.messages);
    setMessages(parsedMessages);
    setLoading(false);
    setSending(false);
    setError('');
  };

  const sendMessage = async () => {
    if (!inputMessage.trim() || activeSendRef.current || loading) return;

    const message = inputMessage.trim();
    const requestId = ++sendRequestRef.current;
    activeSendRef.current = true;
    setInputMessage('');
    setSending(true);
    setError('');

    try {
      let conversation = currentConversation;
      if (!conversation) {
        const operationId = ++conversationOperationRef.current;
        conversation = await aiService.startConversation('AI助手对话');
        if (operationId !== conversationOperationRef.current || requestId !== sendRequestRef.current) return;
        activeSessionIdRef.current = conversation.session_id;
        setCurrentConversation(conversation);
        await loadConversations();
        if (operationId !== conversationOperationRef.current || requestId !== sendRequestRef.current) return;
      }

      const sessionId = conversation.session_id;
      if (activeSessionIdRef.current !== sessionId || requestId !== sendRequestRef.current) return;

      const userMessage: AIMessage = {
        role: 'user',
        content: message,
        timestamp: new Date().toISOString()
      };
      setMessages((current) => activeSessionIdRef.current === sessionId && requestId === sendRequestRef.current
        ? [...current, userMessage]
        : current);

      const response: AIChatResponse = await aiService.sendMessage({
        session_id: sessionId,
        message,
        context: aiService.generateSystemContext()
      });

      if (activeSessionIdRef.current !== sessionId || requestId !== sendRequestRef.current) return;

      const aiMessage: AIMessage = {
        role: 'assistant',
        content: response.message,
        timestamp: new Date().toISOString(),
        tokens: response.tokens_used
      };
      setMessages((current) => activeSessionIdRef.current === sessionId && requestId === sendRequestRef.current
        ? [...current, aiMessage]
        : current);

      await loadUsageStats();
    } catch (error: unknown) {
      if (requestId === sendRequestRef.current) setError(getErrorMessage(error, '发送消息失败'));
    } finally {
      if (requestId === sendRequestRef.current) {
        activeSendRef.current = false;
        setSending(false);
        inputRef.current?.focus();
      }
    }
  };

  const deleteConversation = async (sessionId: string) => {
    const requestId = ++conversationDeleteRequestRef.current;
    const wasActive = activeSessionIdRef.current === sessionId;
    if (wasActive) ++conversationOperationRef.current;
    const operationId = conversationOperationRef.current;
    const previousConversation = currentConversation;
    const previousMessages = messages;
    if (wasActive) {
      ++sendRequestRef.current;
      activeSendRef.current = false;
      activeSessionIdRef.current = null;
      setCurrentConversation(null);
      setMessages([]);
      setSending(false);
    }

    try {
      await aiService.deleteConversation(sessionId);
      if (requestId !== conversationDeleteRequestRef.current) return;
      await loadConversations();
    } catch (error: unknown) {
      if (requestId !== conversationDeleteRequestRef.current) return;
      if (operationId !== conversationOperationRef.current) return;
      if (wasActive) {
        activeSessionIdRef.current = sessionId;
        setCurrentConversation(previousConversation);
        setMessages(previousMessages);
      }
      setError(getErrorMessage(error, '删除对话失败'));
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputMessage(suggestion);
    inputRef.current?.focus();
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* 头部 */}
      <div className="bg-white border-b px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => window.history.back()}
              className="flex items-center gap-2"
            >
              <ArrowLeft className="h-4 w-4" />
              返回
            </Button>
            <div className="flex items-center gap-2">
              <Bot className="h-6 w-6 text-blue-500" />
              <h1 className="text-xl font-semibold">AI助手</h1>
            </div>
          </div>

          {/* 使用统计 */}
          {usageStats && (
            <div className="flex items-center gap-6 text-sm">
              <div className="text-center">
                <div className="font-semibold text-blue-600">{usageStats.total_conversations}</div>
                <div className="text-gray-500">总对话</div>
              </div>
              <div className="text-center">
                <div className="font-semibold text-green-600">
                  {aiService.formatTokenCount(usageStats.total_tokens)}
                </div>
                <div className="text-gray-500">总Token</div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex h-[calc(100vh-80px)]">
        {/* 侧边栏 - 对话列表 */}
        <div className="w-80 bg-white border-r flex flex-col">
          {/* 新对话按钮 */}
          <div className="p-4 border-b">
            <Button
              onClick={startNewConversation}
              disabled={loading || sending}
              className="w-full flex items-center gap-2"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Plus className="h-4 w-4" />
              )}
              新对话
            </Button>
          </div>

          {/* 对话列表 */}
          <div className="flex-1 overflow-y-auto">
            {!conversations || conversations.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                <MessageSquare className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>暂无对话记录</p>
              </div>
            ) : (
              <div className="space-y-1 p-2">
                {conversations.map((conversation) => (
                  <div
                    key={conversation.session_id}
                    className={`p-3 rounded-lg cursor-pointer transition-colors group ${
                      currentConversation?.session_id === conversation.session_id
                        ? 'bg-blue-100 border border-blue-200'
                        : 'hover:bg-gray-50 border border-transparent'
                    }`}
                    onClick={() => selectConversation(conversation)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm truncate">
                          {conversation.title}
                        </div>
                        <div className="text-xs text-gray-500 mt-1 flex items-center gap-2">
                          <Clock className="h-3 w-3" />
                          {new Date(conversation.updated_at).toLocaleDateString()}
                          {conversation.tokens_used > 0 && (
                            <>
                              <Hash className="h-3 w-3" />
                              {aiService.formatTokenCount(conversation.tokens_used)}
                            </>
                          )}
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteConversation(conversation.session_id);
                        }}
                        className="opacity-0 group-hover:opacity-100 p-1 h-auto"
                      >
                        <Trash2 className="h-3 w-3 text-red-500" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 主聊天区域 */}
        <div className="flex-1 flex flex-col bg-white">
          {/* 聊天消息区域 */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {messages.length === 0 ? (
              <div className="text-center py-12">
                <Bot className="h-16 w-16 mx-auto mb-4 text-blue-500 opacity-50" />
                <h3 className="text-lg font-medium text-gray-700 mb-2">
                  欢迎使用AI助手
                </h3>
                <p className="text-gray-500 mb-6">
                  我可以帮助您进行系统配置、语言设置、日期格式等相关问题
                </p>

                {/* 建议问题 */}
                <div className="max-w-2xl mx-auto">
                  <p className="text-sm text-gray-600 mb-3">您可以问我：</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => handleSuggestionClick(suggestion)}
                        className="p-3 text-left bg-blue-50 hover:bg-blue-100 rounded-lg border border-blue-200 transition-colors"
                      >
                        <Sparkles className="h-4 w-4 text-blue-500 mb-1" />
                        <div className="text-sm text-blue-700">{suggestion}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <>
                {messages.map((message, index) => (
                  <div
                    key={index}
                    className={`flex gap-3 ${
                      message.role === 'user' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    {message.role === 'assistant' && (
                      <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                        <Bot className="h-4 w-4 text-blue-600" />
                      </div>
                    )}

                    <div
                      className={`max-w-2xl px-4 py-2 rounded-lg ${
                        message.role === 'user'
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      <div className="whitespace-pre-wrap">{message.content}</div>
                      <div className={`text-xs mt-1 flex items-center gap-2 ${
                        message.role === 'user' ? 'text-blue-100' : 'text-gray-500'
                      }`}>
                        <Clock className="h-3 w-3" />
                        {new Date(message.timestamp).toLocaleTimeString()}
                        {message.tokens && (
                          <>
                            <Hash className="h-3 w-3" />
                            {message.tokens} tokens
                          </>
                        )}
                      </div>
                    </div>

                    {message.role === 'user' && (
                      <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center flex-shrink-0">
                        <User className="h-4 w-4 text-gray-600" />
                      </div>
                    )}
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </>
            )}
          </div>

          {/* 错误提示 */}
          {error && (
            <div className="mx-6 mb-2 p-3 bg-red-50 border border-red-200 text-red-600 rounded-lg flex items-center gap-2">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}

          {/* 输入区域 */}
          <div className="border-t p-6">
            <div className="flex gap-2">
              <Input
                ref={inputRef}
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder="输入您的问题..."
                disabled={sending}
                className="flex-1"
              />
              <Button
                onClick={sendMessage}
                disabled={!inputMessage.trim() || sending}
                className="px-4"
              >
                {sending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};