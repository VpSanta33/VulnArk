import { useState, ComponentProps } from 'react';
import { ExtraProps } from 'react-markdown';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import {
  Copy,
  Check,
  Code,
  Eye,
  Edit,
  Maximize2,
  Minimize2
} from 'lucide-react';
import { Button } from '../ui/Button';
import { sanitizeHTML } from '../../lib/sanitizeHTML';

export interface KnowledgeContentRendererProps {
  content: string;
  contentType?: 'html' | 'markdown' | 'text';
  className?: string;
  showToolbar?: boolean;
  editable?: boolean;
  onEdit?: (content: string) => void;
}

export function KnowledgeContentRenderer({
  content,
  contentType = 'html',
  className = '',
  showToolbar = true,
  editable = false,
  onEdit
}: KnowledgeContentRendererProps) {
  const [viewMode, setViewMode] = useState<'rendered' | 'source'>('rendered');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy content:', error);
    }
  };

  const handleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  const renderContent = () => {
    if (viewMode === 'source') {
      return (
        <pre className="bg-gray-50 p-4 rounded-lg overflow-auto text-sm font-mono whitespace-pre-wrap">
          <code>{content}</code>
        </pre>
      );
    }

    switch (contentType) {
      case 'html':
        return (
          <div
            className="prose prose-gray max-w-none prose-headings:text-gray-900 prose-h1:text-2xl prose-h2:text-xl prose-h3:text-lg prose-p:text-gray-700 prose-li:text-gray-700 prose-strong:text-gray-900 prose-code:bg-gray-100 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-gray-900 prose-pre:text-gray-100"
            dangerouslySetInnerHTML={{ __html: sanitizeHTML(content) }}
          />
        );

      case 'markdown':
        return (
          <div className="prose prose-gray max-w-none prose-headings:text-gray-900 prose-h1:text-2xl prose-h2:text-xl prose-h3:text-lg prose-p:text-gray-700 prose-li:text-gray-700 prose-strong:text-gray-900 prose-code:bg-gray-100 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-gray-900 prose-pre:text-gray-100">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              rehypePlugins={[rehypeHighlight]}
              components={{
                // Custom components for better styling
                code: ({ inline, className, children, ...props }: ComponentProps<'code'> & ExtraProps & { inline?: boolean }) => {
                  delete props.node;
                  const match = /language-(\w+)/.exec(className || '');
                  return !inline && match ? (
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                      <code className={className} {...props}>
                        {children}
                      </code>
                    </pre>
                  ) : (
                    <code className="bg-gray-100 text-gray-800 px-1 py-0.5 rounded text-sm" {...props}>
                      {children}
                    </code>
                  );
                },
                blockquote: ({ children }) => (
                  <blockquote className="border-l-4 border-blue-500 bg-blue-50 p-4 my-4 italic">
                    {children}
                  </blockquote>
                ),
                table: ({ children }) => (
                  <div className="overflow-x-auto my-4">
                    <table className="min-w-full border-collapse border border-gray-300">
                      {children}
                    </table>
                  </div>
                ),
                th: ({ children }) => (
                  <th className="border border-gray-300 bg-gray-100 px-4 py-2 text-left font-semibold">
                    {children}
                  </th>
                ),
                td: ({ children }) => (
                  <td className="border border-gray-300 px-4 py-2">
                    {children}
                  </td>
                ),
              }}
            >
              {content}
            </ReactMarkdown>
          </div>
        );

      case 'text':
      default:
        return (
          <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
            {content}
          </div>
        );
    }
  };

  const containerClasses = isFullscreen 
    ? 'fixed inset-0 z-50 bg-white p-6 overflow-auto'
    : className;

  return (
    <div className={containerClasses}>
      {showToolbar && (
        <div className="flex items-center justify-between mb-4 p-3 bg-gray-50 rounded-lg border">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setViewMode(viewMode === 'rendered' ? 'source' : 'rendered')}
              className="flex items-center gap-2"
            >
              {viewMode === 'rendered' ? (
                <>
                  <Code className="h-4 w-4" />
                  查看源码
                </>
              ) : (
                <>
                  <Eye className="h-4 w-4" />
                  渲染视图
                </>
              )}
            </Button>

            {editable && onEdit && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onEdit(content)}
                className="flex items-center gap-2"
              >
                <Edit className="h-4 w-4" />
                编辑
              </Button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopy}
              className="flex items-center gap-2"
            >
              {copied ? (
                <>
                  <Check className="h-4 w-4 text-green-600" />
                  已复制
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4" />
                  复制
                </>
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={handleFullscreen}
              className="flex items-center gap-2"
            >
              {isFullscreen ? (
                <>
                  <Minimize2 className="h-4 w-4" />
                  退出全屏
                </>
              ) : (
                <>
                  <Maximize2 className="h-4 w-4" />
                  全屏查看
                </>
              )}
            </Button>
          </div>
        </div>
      )}

      <div className={`${isFullscreen ? 'flex-1' : ''} overflow-auto`}>
        {renderContent()}
      </div>


    </div>
  );
}
